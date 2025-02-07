#include "tau_journal.h"

#ifdef CONFIG_EXT4_TAU_JOURNAL
#include "ext4.h"
#include "ext4_jbd2.h"
#include "linux/buffer_head.h"
#include "linux/fs.h"
#include "linux/jbd2.h"
#include "linux/printk.h"
#include "linux/types.h"
#include <linux/timer.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include "linux/writeback.h"

void tjournal_init_inode(struct inode *inode)
{
	struct ext4_inode_info *ei;

	ei = EXT4_I(inode);
	ei->i_journalled_da_tree.root = NULL;
	spin_lock_init(&ei->i_journalled_da_tree.lock);
#ifdef CONFIG_EXT4_TAU_JOURNAL_ATOMIC_FILE
	memset(&ei->i_atomic_master, 0, sizeof(ei->i_atomic_master));
#endif
}

bool has_da_journalled(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	return ei->i_journalled_da_tree.root != NULL;
}

void __print_da_tree_all(struct tjournal_da_node *node, int depth);

void __print_da_tree_all(struct tjournal_da_node *node, int depth)
{
	if (node->left)
		__print_da_tree_all(node->left, depth + 1);

	pr_info("node(%lu, %d), depth(%d)\n", node->start, node->len, depth);

	if (node->right)
		__print_da_tree_all(node->right, depth + 1);
}

void print_tjournal_da_tree_all(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct tjournal_da_tree *root = &ei->i_journalled_da_tree;

	if (!root->root) {
		printk("No journalled data blocks\n");
		return;
	}
	__print_da_tree_all(root->root, 0);
}

bool tjournal_try_to_free_buffers(struct folio *folio)
{
	struct ext4_inode_info *ei;
	struct inode *inode;
	struct address_space *mapping = folio->mapping;
	bool ret;

	BUG_ON(!mapping);
	inode = mapping->host;
	ei = EXT4_I(inode);

	if (!ext4_should_tjournal(inode)) {
		journal_t *journal = EXT4_JOURNAL(folio->mapping->host);
		return jbd2_journal_try_to_free_buffers(journal, folio);
	}
	
	if (S_ISDIR(inode->i_mode))
		return false;

	/* If there exist pages committed, which have to be checkpointed later */
	ret = has_da_journalled(inode);
	return ret;
}

static inline void __buffer_unlink_first(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	jh->b_cpnext->b_cpprev = jh->b_cpprev;
	jh->b_cpprev->b_cpnext = jh->b_cpnext;
	if (transaction->t_checkpoint_list == jh) {
		transaction->t_checkpoint_list = jh->b_cpnext;
		if (transaction->t_checkpoint_list == jh)
			transaction->t_checkpoint_list = NULL;
	}
}

static void __flush_batch(journal_t *journal, int *batch_count)
{
	int i;
	struct blk_plug plug;
	struct buffer_head *bh;

	blk_start_plug(&plug);
	for (i = 0; i < *batch_count; i++) {
		bh = journal->tjournal_chkpt_bhs[i];
		lock_buffer(bh);
		bh->b_end_io = end_buffer_write_sync;
		get_bh(bh);
		submit_bh(REQ_OP_WRITE | REQ_SYNC, bh);
	}
	blk_finish_plug(&plug);

	for (i = 0; i < *batch_count; i++) {
		struct buffer_head *bh = journal->tjournal_chkpt_bhs[i];
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
	}
	*batch_count = 0;
}

int tjournal_writepages(struct address_space *mapping)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.range_start = 0,
		.range_end = LLONG_MAX,
	};

	return ext4_tjournal_writepages(mapping, &wbc);
}

static int tjournal_start_checkpoint(journal_t *journal)
{
	struct journal_head *jh;
	struct buffer_head *bh;
	transaction_t *transaction;
	tid_t this_tid;
	pgoff_t delayed = -1; /* Just for error checking */
	int result, batch_count = 0;

	/*
	 * First thing: if there are any transactions in the log which
	 * don't need checkpointing, just eliminate them from the
	 * journal straight away.
	 */
	result = jbd2_cleanup_journal_tail(journal);
	if (result <= 0)
		return result;

	spin_lock(&journal->j_list_lock);
	if (!journal->j_checkpoint_transactions) {
		wait_event(journal->j_wait_done_commit,
			   journal->j_checkpoint_transactions != NULL);
		goto out;
	}

	transaction = journal->j_checkpoint_transactions;
	if (transaction->t_chp_stats.cs_chp_time == 0)
		transaction->t_chp_stats.cs_chp_time = jiffies;
	this_tid = transaction->t_tid;

	tjk_debug("Target transaction ID => [%d]\n", this_tid);

restart:
	/* Somebody already handles this transaction? */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;

	while (transaction->t_checkpoint_list) {
		jh = transaction->t_checkpoint_list;
		bh = jh2bh(jh);

		// tj_debug("checkpoint block(%d)\n", (int)bh->b_blocknr);
		if (buffer_locked(bh)) {
			tj_debug("wait on buffer\n");
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			__brelse(bh);
			goto retry;
		}

		/* We need to allocate delayed data blocks here */
		if (buffer_delay(bh)) {
			tj_debug("delayed block(%lu) require allocation!\n",
				 bh->b_page->index);
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			if (delayed == bh->b_page->index) {
				pr_err("da not worked by writepages %lu\n",
				       bh->b_page->index);
			}
			BUG_ON(delayed == bh->b_page->index);
			BUG_ON(bh->b_page->mapping == NULL);
			mutex_unlock(&journal->j_checkpoint_mutex);
			ihold(bh->b_page->mapping->host);
			tjournal_writepages(bh->b_page->mapping);
			iput(bh->b_page->mapping->host);
			mutex_lock_io(&journal->j_checkpoint_mutex);
			// TODO: error handling
			delayed = bh->b_page->index;
			__brelse(bh);
			goto retry;
		}

		/* If this buffer involved in current transcation */
		if (jh->b_transaction != NULL) {
			transaction_t *t = jh->b_transaction;
			tid_t tid = t->t_tid;

			transaction->t_chp_stats.cs_forced_to_close++;
			spin_unlock(&journal->j_list_lock);
			tj_debug("buffer(%llu) wait on commit tid(%d)\n",
				 bh->b_blocknr, tid);

			/* The journal thread is dead; so starting and waiting for a commit
			 * to finish will cause us to wait for a _very_ long time. */
			if (unlikely(journal->j_flags & JBD2_UNMOUNT))
				printk(KERN_ERR
				       "JBD2: %s: Waiting for Godot: block %llu\n",
				       journal->j_devname,
				       (unsigned long long)bh->b_blocknr);

			if (batch_count)
				__flush_batch(journal, &batch_count);
			jbd2_log_start_commit(journal, tid);
			/*
			 * jbd2_journal_commit_transaction() may want
			 * to take the checkpoint_mutex if JBD2_FLUSHED
			 * is set, jbd2_update_log_tail() called by
			 * jbd2_journal_commit_transaction() may also take
			 * checkpoint_mutex.  So we need to temporarily
			 * drop it.
			 */
			mutex_unlock(&journal->j_checkpoint_mutex);
			jbd2_log_wait_commit(journal, tid);
			mutex_lock_io(&journal->j_checkpoint_mutex);
			spin_lock(&journal->j_list_lock);
			goto restart;
		}

		if (!buffer_taudirty(bh)) {
			// tj_debug("not dirty remove it\n");
			if (__jbd2_journal_remove_checkpoint(jh))
				/* The transaction was released; we're done */
				goto out;
			continue;
		} else
			clear_buffer_taudirty(bh); /* Let's do writeback */

		// tj_debug("queing block(%d)\n", (int)bh->b_blocknr);
		BUFFER_TRACE(bh, "queue");
		get_bh(bh);
		J_ASSERT_BH(bh, !buffer_jwrite(bh));
		journal->tjournal_chkpt_bhs[batch_count++] = bh;
		transaction->t_chp_stats.cs_written++;
		if ((batch_count == JBD2_NR_BATCH) || need_resched() ||
		    spin_needbreak(&journal->j_list_lock))
			goto unlock_and_flush;
	}

	if (batch_count) {
unlock_and_flush:
		spin_unlock(&journal->j_list_lock);
retry:
		if (batch_count)
			__flush_batch(journal, &batch_count);
		spin_lock(&journal->j_list_lock);
		goto restart;
	}

out:
	spin_unlock(&journal->j_list_lock);
	result = jbd2_cleanup_journal_tail(journal);
	tj_debug("return with(%d)\n", result);
	return (result < 0) ? result : 0;
}

/* based on jbd2_journal_flush() */
static int tjournal_flush_all(journal_t *journal)
{
	int err = 0;
	transaction_t *transaction = NULL;

	tjk_debug("start flushing all journal to disk\n");

	write_lock(&journal->j_state_lock);

	/* Force everything buffered to the log... */
	if (journal->j_running_transaction) {
		transaction = journal->j_running_transaction;
		write_unlock(&journal->j_state_lock);
		tj_debug("start commit running transaction(%d)\n",
			 transaction->t_tid);
		jbd2_log_start_commit(journal, transaction->t_tid);
		write_lock(&journal->j_state_lock);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	/* Wait for the log commit to complete... */
	if (transaction) {
		tid_t tid = transaction->t_tid;

		write_unlock(&journal->j_state_lock);
		tj_debug("wait transaction(%d) being committed\n", tid);
		jbd2_log_wait_commit(journal, tid);
	} else
		write_unlock(&journal->j_state_lock);

	/* ...and flush everything in the log out to disk. */
	spin_lock(&journal->j_list_lock);
	while (!err && journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock_io(&journal->j_checkpoint_mutex);
		err = tjournal_start_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		spin_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	tj_debug("all transaction being checkpointed\n");
	if (is_journal_aborted(journal))
		return -EIO;

	mutex_lock_io(&journal->j_checkpoint_mutex);
	if (!err) {
		err = jbd2_cleanup_journal_tail(journal);
		if (err < 0) {
			mutex_unlock(&journal->j_checkpoint_mutex);
			goto out;
		}
		err = 0;
	}

	/* Finally, mark the journal as really needing no recovery.
	 * This sets s_start==0 in the underlying superblock, which is
	 * the magic code for a fully-recovered superblock.  Any future
	 * commits of data to the journal will restore the current
	 * s_start value. */
	tjournal_mark_journal_empty(journal, REQ_SYNC | REQ_FUA);

	mutex_unlock(&journal->j_checkpoint_mutex);
	write_lock(&journal->j_state_lock);
	J_ASSERT(!journal->j_running_transaction);
	J_ASSERT(!journal->j_committing_transaction);
	J_ASSERT(!journal->j_checkpoint_transactions);
	J_ASSERT(journal->j_head == journal->j_tail);
	J_ASSERT(journal->j_tail_sequence == journal->j_transaction_sequence);
	write_unlock(&journal->j_state_lock);
out:

	return err;
}

/**
 * tjournald - Tau Journal Daemon for managing journal area
 *
 *   - It is responsible for writeback of committed blocks to filesystem area
 *   - If left journal area is not enough, it starts checkpointing
 *   - Not use VM subsystem writeback mechanism
 *   - Delayed allocation supports 
 *
 */
static int tjournald(void *arg)
{
	journal_t *journal = arg;

	set_freezable();

	journal->tjournal_task = current;
	wake_up(&journal->j_wait_done_checkpoint);

	/* checkpoint does not require the j_state_lock
     *  (from jbd2_journal_flush()) */

loop:
	if (journal->j_flags & (JBD2_UNMOUNT | JBD2_FORCE_CHECKPOINT)) {
		tjournal_flush_all(journal);
		goto end_loop;
	}

	if (journal->j_requested_checkpoint) {
		/* if a thread request for journal space */
		tjk_debug("Requested from user thread\n");
		while (jbd2_log_space_left(journal) <
		       journal->j_requested_checkpoint) {
			mutex_lock_io(&journal->j_checkpoint_mutex);
			tjournal_start_checkpoint(journal);
			mutex_unlock(&journal->j_checkpoint_mutex);
		}
		read_lock(&journal->j_state_lock);
		journal->j_requested_checkpoint = 0;
		read_unlock(&journal->j_state_lock);
	} else {
		/* Do checkpoint until journal area is enough */
		tjk_debug("Requested from tjournald\n");
		while (tjournal_need_checkpoint(journal)) {
			mutex_lock_io(&journal->j_checkpoint_mutex);
			tjournal_start_checkpoint(journal);
			mutex_unlock(&journal->j_checkpoint_mutex);
		}
	}

	tjk_debug(
		"Finish checkpoint. left blocks(%lu/%luMiB) total blocks(%d/%luMB).\n\n",
		jbd2_log_space_left(journal),
		(jbd2_log_space_left(journal) * journal->j_blocksize) >> 20,
		journal->j_total_len,
		((unsigned long)journal->j_total_len * journal->j_blocksize) >>
			20);

	wake_up(&journal->j_wait_done_checkpoint);
	if (freezing(current)) {
		write_unlock(&journal->j_state_lock);
		try_to_freeze();
		write_lock(&journal->j_state_lock);
	} else {
		/* Wait until next request */
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_checkpoint, &wait,
				TASK_INTERRUPTIBLE);
		schedule();
		finish_wait(&journal->j_wait_checkpoint, &wait);
	}

	tjd_debug("tjournald wakes\n");

	goto loop;

end_loop:
	journal->tjournal_task = NULL;
	wake_up(&journal->j_wait_done_checkpoint);
	tjd_debug("Tau Journal thread exiting.\n");
	return 0;
}

int tjournal_start_thread(journal_t *journal)
{
	struct task_struct *t;

	t = kthread_run(tjournald, journal, "tjournald/%s", journal->j_devname);
	if (IS_ERR(t))
		return PTR_ERR(t);

	wait_event(journal->j_wait_done_checkpoint,
		   journal->tjournal_task != NULL);
	return 0;
}

static struct tjournal_da_node *create_da_node(unsigned long value,
					       unsigned int length)
{
	struct tjournal_da_node *node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		pr_err("Failed to allocate memory for extent_node\n");
		return NULL;
	}
	node->start = value;
	node->len = length;
	node->left = NULL;
	node->right = NULL;
	return node;
}

static struct tjournal_da_node *least_node(struct tjournal_da_node *node,
					   struct tjournal_da_node **prev)
{
	while (node->left) {
		*prev = node;
		node = node->left;
	}
	return node;
}

static struct tjournal_da_node *most_node(struct tjournal_da_node *node,
					  struct tjournal_da_node **prev)
{
	while (node->right) {
		*prev = node;
		node = node->right;
	}
	return node;
}

static void __insert_da_node(struct tjournal_da_node *node, pgoff_t index)
{
	/* Already exist in the da_tree */
	if (index == node->start ||
	    (index > node->start && index < node->start + node->len))
		return;

	/* Index is smaller than this node */
	if (index < node->start) {
		/* Direct merge with left node */
		if (index + 1 == node->start) {
			// tj_debug(
			// 	"Page(%lu) be merged with node(%lu, %d)_left\n",
			// 	index, node->start, node->len);
			node->start = index;
			node->len++;

			/* If merged node has a child, we need to check child can be merged */
			if (node->left) {
				struct tjournal_da_node *left = node->left;

				// find right most node
				if (left->right) {
					struct tjournal_da_node *most, *prev;
					// tj_debug(
					// 	"left_child(%lu, %u) has right(%lu, %u)\n",
					// 	left->start, left->len,
					// 	left->right->start,
					// 	left->right->len);

					most = most_node(left, &prev);
					if (most != left &&
					    most->start + most->len ==
						    node->start) {
						node->start = most->start;
						node->len += most->len;
						prev->right = most->left;
						// tj_debug(
						// 	"most_node(%lu, %u) merged to parent(%lu, %u)\n",
						// 	most->start, most->len,
						// 	node->start, node->len);
						kfree(most);
						return;
					}
				}

				if (left->start + left->len == node->start) {
					// tj_debug(
					// 	"left_child(%lu, %u) merged to parent(%lu, %u)\n",
					// 	left->start, left->len,
					// 	node->start, node->len);
					BUG_ON(left->right);
					node->start = left->start;
					node->len += left->len;
					node->left = left->left;
					kfree(left);
					return;
				}
			}
		}
		/* Make left node if not exist */
		else if (!node->left) {
			// tj_debug(
			// 	"create new node(%lu, 1) as left child of node(%lu, %d)\n",
			// 	index, node->start, node->len);
			node->left = create_da_node(index, 1);
		} else
			__insert_da_node(node->left, index);
	}

	/* Index is bigger than this node */
	else {
		/* Direct merge with right node */
		if (index == node->start + node->len) {
			// tj_debug(
			// 	"Page(%lu) be merged with node(%lu, %d)_right\n",
			// 	index, node->start, node->len);
			node->len++;

			/* check child can be merged */
			if (node->right) {
				struct tjournal_da_node *right = node->right;

				// find left least node
				if (right->left) {
					struct tjournal_da_node *least, *prev;
					// tj_debug(
					// 	"right_child(%lu, %u) has left(%lu, %u)\n",
					// 	right->start, right->len,
					// 	right->left->start,
					// 	right->left->len);

					least = least_node(right, &prev);
					if (least != right &&
					    node->start + node->len ==
						    least->start) {
						node->len += least->len;
						prev->left = least->right;
						// tj_debug(
						// 	"least_node(%lu, %u) merged to parent(%lu, %u)\n",
						// 	least->start,
						// 	least->len, node->start,
						// 	node->len);
						kfree(least);
						return;
					}
				}

				if (node->start + node->len == right->start) {
					// tj_debug(
					// 	"right_child(%lu, %u) merged to parent(%lu, %u)\n",
					// 	right->start, right->len,
					// 	node->start, node->len);
					BUG_ON(right->left);
					node->len += right->len;
					node->right = right->right;
					kfree(right);
					return;
				}
			}
		}
		/* Make right node if not exist */
		else if (!node->right) {
			// tj_debug(
			// 	"create new node(%lu, 1) as right child of node(%lu, %d)\n",
			// 	index, node->start, node->len);
			node->right = create_da_node(index, 1);
		} else /* lets do next iterative */
			__insert_da_node(node->right, index);
	}
}

int tjournal_need_checkpoint(journal_t *journal)
{
	return (jbd2_log_space_left(journal) < journal->j_checkpoint_threshold);
}

static void __insert_da_journalled(struct tjournal_da_tree *tree, pgoff_t index)
{
	spin_lock(&tree->lock);
	// tjk_debug("push index(%lu)\n", index);
	if (!tree->root)
		tree->root = create_da_node(index, 1);
	else
		__insert_da_node(tree->root, index);
	spin_unlock(&tree->lock);
}

void insert_da_journalled(struct inode *inode, unsigned long index)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	__insert_da_journalled(&ei->i_journalled_da_tree, index);
}

static struct tjournal_da_node *
__find_node_next_in_left(struct tjournal_da_node *node,
			 struct tjournal_da_node **next, unsigned long index)
{
	/* Check this node contains the requested index */
	if (index >= node->start && index < node->start + node->len)
		return node;

	if ((*next)->start > node->start && index < node->start)
		*next = node;

	if (index < node->start && node->left)
		return __find_node_next_in_left(node->left, next, index);
	else if (index > (node->start + node->len - 1) && node->right)
		return __find_node_next_in_left(node->right, next, index);

	return NULL;
}

static struct tjournal_da_node *
__find_node_next_in_right(struct tjournal_da_node *node,
			  struct tjournal_da_node **next, unsigned long index)
{
	/* Check this node contains the requested index */
	if (index >= node->start && index < node->start + node->len)
		return node;

	if ((*next) == NULL && index < node->start)
		*next = node;

	if ((*next)->start > node->start && index < node->start)
		*next = node;

	if (index < node->start && node->left)
		return __find_node_next_in_right(node->left, next, index);
	else if (index > (node->start + node->len - 1) && node->right)
		return __find_node_next_in_right(node->right, next, index);

	return NULL;
}

static struct tjournal_da_node *
find_node_and_next(struct tjournal_da_node *root,
		   struct tjournal_da_node **next, unsigned long index)
{
	struct tjournal_da_node *ret = NULL;

	if (index >= root->start && index < root->start + root->len)
		ret = root;
	else {
		if (index < root->start) {
			*next = root;
			if (root->left)
				ret = __find_node_next_in_left(root->left, next,
							       index);
		} else {
			if (root->right)
				ret = __find_node_next_in_right(root->right,
								next, index);
		}
	}

	return ret;
}

static int __lookup_da_journalled(struct tjournal_da_tree *tree, pgoff_t *index,
				  unsigned int *len)
{
	struct tjournal_da_node *next, *node;
	node = next = NULL;

	spin_lock(&tree->lock);
	node = find_node_and_next(tree->root, &next, *index);
	spin_unlock(&tree->lock);

	if (!node) {
		pgoff_t old = *index;
		*index = next ? next->start : (pgoff_t)-1;
		*len = 0;
		tj_debug(" (%s) index(%lu) not found next is (%lu) \n", __func__, old, *index);
		return 0;
	}

	/* next index will be modified by pagevec_lookup_range_tag() */
	*len = node->start - *index + node->len;
	tj_debug(" (%s) index(%lu) found in node(%lu, %u)\n", __func__, *index,
		 node->start, node->len);
	return 1;
}

/**
 * @brief Lookup delayed allocation state of file
 * 
 * @param len (extent length started from index)
 * @return 0: not found, 1: found
 */
int lookup_da_journalled(struct inode *inode, pgoff_t *index, unsigned int *len)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	/* nothing on this file */
	if (ei->i_journalled_da_tree.root == NULL) {
		*index = (pgoff_t)-1;
		*len = 0;
		return 0;
	}

	return __lookup_da_journalled(&ei->i_journalled_da_tree, index, len);
}

static struct tjournal_da_node *
__find_node_with_prev(struct tjournal_da_node *node,
		      struct tjournal_da_node **prev, unsigned long index)
{
	/* Check this node contains the requested index */
	if (index >= node->start && index < node->start + node->len)
		return node;

	if (index < node->start && node->left) {
		*prev = node;
		return __find_node_with_prev(node->left, prev, index);
	} else if (index > (node->start + node->len - 1) && node->right) {
		*prev = node;
		return __find_node_with_prev(node->right, prev, index);
	}

	return NULL;
}

static struct tjournal_da_node *
find_node_with_prev(struct tjournal_da_node *node,
		    struct tjournal_da_node **prev, unsigned long index)
{
	/* Check this node contains the requested index */
	if (index >= node->start && index < node->start + node->len)
		return node;

	*prev = node;
	if (index < node->start && node->left)
		return __find_node_with_prev(node->left, prev, index);

	if (index > node->start && node->right)
		return __find_node_with_prev(node->right, prev, index);

	return NULL;
}

static int __delete_da_journalled(struct tjournal_da_tree *tree, pgoff_t start,
				  unsigned int len)
{
	struct tjournal_da_node *temp, *prev, *node;
	pgoff_t end = start + len;
	int ret = 0;

	node = prev = temp = NULL;
	spin_lock(&tree->lock);
	node = find_node_with_prev(tree->root, &prev, start);
	if (!node) {
		ret = -EINVAL;
		goto unlock;
	}

	/* Split nodes context start */
	/* 1. We found exact matching node */
	if (start == node->start && len == node->len) {
		/* node is root*/
		if (node == tree->root) {
			if (node->left) {
				temp = most_node(node->left, &prev);
				if (temp == node->left) {
					temp->right = node->right;
					tree->root = temp;
					kfree(node);
				} else {
					BUG_ON(!prev);
					prev->right = NULL;
					least_node(temp, &prev)->left =
						node->left;
					temp->right = node->right;
					tree->root = temp;
					kfree(node);
				}
			} else if (node->right) {
				temp = least_node(node->right, &prev);
				if (temp == node->right) {
					temp->left = node->left;
					tree->root = temp;
					kfree(node);
				} else {
					BUG_ON(!prev);
					prev->left = NULL;
					most_node(temp, &prev)->right =
						node->right;
					temp->left = node->left;
					tree->root = temp;
					kfree(node);
				}
			} else {
				tree->root = NULL;
				kfree(node);
			}
			/* all done */
			goto unlock;
		}
		/* node is non-root */
		else {
			struct tjournal_da_node *nprev = prev;
			BUG_ON(!nprev);
			if (node->left) {
				temp = most_node(node->left, &prev);
				if (temp == node->left) {
					temp->right = node->right;
					if (nprev->start > node->start)
						nprev->left = temp;
					else
						nprev->right = temp;
					kfree(node);
				} else {
					prev->right = NULL;
					least_node(temp, &prev)->left =
						node->left;
					temp->right = node->right;
					if (nprev->start > node->start)
						nprev->left = temp;
					else
						nprev->right = temp;
					kfree(node);
				}
			} else if (node->right) {
				temp = least_node(node->right, &prev);
				if (temp == node->right) {
					temp->left = node->left;
					if (nprev->start > node->start)
						nprev->left = temp;
					else
						nprev->right = temp;
					kfree(node);
				} else {
					prev->left = NULL;
					most_node(temp, &prev)->right =
						node->right;
					temp->left = node->left;
					if (nprev->start > node->start)
						nprev->left = temp;
					else
						nprev->right = temp;
					kfree(node);
				}
			} else {
				if (nprev->start > node->start)
					nprev->left = NULL;
				else
					nprev->right = NULL;
				kfree(node);
			}
			/* all done */
			goto unlock;
		}
	}

	if (start == node->start) {
		/* start is same */
		BUG_ON(node->len < len);
		node->start = end;
		node->len -= len;
	} else if (end == node->start + node->len) {
		/* end is same*/
		BUG_ON(node->len < len);
		node->len -= len;
	} else {
		/* in the middle of range */
		struct tjournal_da_node *new_node;

		new_node = create_da_node(end, node->start + node->len - end);
		if (!new_node) {
			ret = -ENOMEM;
			goto unlock;
		}
		new_node->right = node->right;
		node->right = new_node;
		BUG_ON(node->len < start - node->start);
		node->len = start - node->start;
	}

unlock:
	spin_unlock(&tree->lock);

	if (ret < 0) {
		pr_err("Failed to delete node(%lu, %u) ret(%d)\n", start, len, ret);
		ret = 0;
	}

	return ret;
}

int delete_da_journalled(struct inode *inode, pgoff_t start, unsigned int len)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	// tj_debug("delete_da_journalled(%lu, %u)\n", start, len);
	return __delete_da_journalled(&ei->i_journalled_da_tree, start, len);
}

static void free_da_journalled(struct tjournal_da_node *node)
{
	if (!node)
		return;

	if (node->left)
		free_da_journalled(node->left);
	if (node->right)
		free_da_journalled(node->right);

	kfree(node);
}

static struct tjournal_da_node *
__truncate_da_journalled(struct tjournal_da_node *node, pgoff_t start)
{
	if (!node)
		return NULL;

	if (node->start > start) {
		free_da_journalled(node);
		return NULL;
	}

	if (node->start <= start && node->start + node->len > start) {
		node->len = start - node->start;
		if (node->right) {
			free_da_journalled(node->right);
			node->right = NULL;
		}
		return node;
	}

	node->left = __truncate_da_journalled(node->left, start);
	node->right = __truncate_da_journalled(node->right, start);

	return node;
}

/**
 * @brief truncate da_tree from start (inclusive)
 *
*/
int truncate_da_journalled(struct inode *inode, pgoff_t start)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct tjournal_da_tree *tree = &ei->i_journalled_da_tree;

	tj_debug("truncate_da_journalled(%lu)\n", start);

	spin_lock(&tree->lock);
	tree->root = __truncate_da_journalled(tree->root, start);
	spin_unlock(&tree->lock);
	return 0;
}

#endif /* CONFIG_EXT4_TAU_JOURNAL */
