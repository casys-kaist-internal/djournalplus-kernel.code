#include "tau_journal.h"
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
}

bool has_da_journalled(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	return ei->i_journalled_da_tree.root != NULL;
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

	if (!ext4_should_journal_plus(inode)) {
		journal_t *journal = EXT4_JOURNAL(folio->mapping->host);
		return jbd2_journal_try_to_free_buffers(journal, folio);
	}

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

/*
 * Move a buffer from the checkpoint list to the checkpoint io list
 *
 * Called with j_list_lock held
 */
static inline void __buffer_relink_io(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);

	if (!transaction->t_checkpoint_io_list) {
		jh->b_cpnext = jh->b_cpprev = jh;
	} else {
		jh->b_cpnext = transaction->t_checkpoint_io_list;
		jh->b_cpprev = transaction->t_checkpoint_io_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_io_list = jh;
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
	if (!journal->j_checkpoint_transactions)
		goto out;

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

		tjk_debug("chkpt target block: %llu\n",
			  (unsigned long long)bh->b_blocknr);
		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			__brelse(bh);
			goto retry;
		}

		/* We need to allocate delayed data blocks here */
		if (buffer_delay(bh)) {
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			BUG_ON(bh->b_page->mapping == NULL);
			tjournal_writepages(bh->b_page->mapping);
			BUG_ON(buffer_delay(bh));
			// TODO: error handling
			__brelse(bh);
			goto retry;
		}

		// 해당 블록이 현재 러닝 트랜잭션에 포함된 경우
		if (jh->b_transaction != NULL) {
			transaction_t *t = jh->b_transaction;
			tid_t tid = t->t_tid;

			transaction->t_chp_stats.cs_forced_to_close++;
			spin_unlock(&journal->j_list_lock);

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
			if (__jbd2_journal_remove_checkpoint(jh))
				/* The transaction was released; we're done */
				goto out;
			continue;
		} else
			clear_buffer_taudirty(bh); /* Let's do writeback */

		BUFFER_TRACE(bh, "queue");
		get_bh(bh);
		J_ASSERT_BH(bh, !buffer_jwrite(bh));
		journal->tjournal_chkpt_bhs[batch_count++] = bh;
		__buffer_relink_io(jh);
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

restart2:
	/* Did somebody clean up the transaction in the meanwhile? */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;

	while (transaction->t_checkpoint_io_list) {
		jh = transaction->t_checkpoint_io_list;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			/* the journal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			spin_lock(&journal->j_list_lock);
			goto restart2;
		}

		/*
		 * Now in whatever state the buffer currently is, we
		 * know that it has been written out and so we can
		 * drop it from the list
		 */
		if (__jbd2_journal_remove_checkpoint(jh))
			break;
	}

out:
	spin_unlock(&journal->j_list_lock);
	result = jbd2_cleanup_journal_tail(journal);

	return (result < 0) ? result : 0;
}

/* based on jbd2_journal_flush() */
static int tjournal_flush_all(journal_t *journal)
{
	int err = 0;
	transaction_t *transaction = NULL;

	tjk_debug("start\n");

	write_lock(&journal->j_state_lock);

	/* Force everything buffered to the log... */
	if (journal->j_running_transaction) {
		transaction = journal->j_running_transaction;
		write_unlock(&journal->j_state_lock);
		jbd2_log_start_commit(journal, transaction->t_tid);
		write_lock(&journal->j_state_lock);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	/* Wait for the log commit to complete... */
	if (transaction) {
		tid_t tid = transaction->t_tid;

		write_unlock(&journal->j_state_lock);
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

	/* Do checkpoint until journal area is enough */
	while ((jbd2_log_space_left(journal) / journal->j_total_len) <
	       journal->j_checkpoint_threshold)
		tjournal_start_checkpoint(journal);

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
	tjc_debug("node:%p, node start:%lu, node:len%d index: %lu\n", node,
		  node->start, node->len, index);

	// 인덱스가 노드보다 작을경우
	if (index < node->start) {
		// 노드에 병합.
		if (index + 1 == node->start) {
			struct tjournal_da_node *left = node->left;
			node->start = index;
			node->len++;

			if (left) {
				if (left->right) {
					struct tjournal_da_node *most, *prev;

					most = most_node(left, &prev);
					if (most != left &&
					    most->start + most->len - 1 ==
						    node->start) {
						node->start = most->start;
						node->len += most->len;
						prev->right = NULL;
						kfree(most);
						return;
					}
				}

				/* Direct merge with left node */
				if (left->start + left->len - 1 ==
				    node->start) {
					BUG_ON(left->right);
					node->start = left->start;
					node->len += left->len;
					node->left = left->left;
					kfree(left);
					return;
				}
			}
		}
		// 왼쪽 노드 생성
		else if (!node->left)
			node->left = create_da_node(index, 1);
		else
			__insert_da_node(node->left, index);
	}

	// 인덱스가 노드보다 큰 경우
	if (index > node->start + node->len) {
		// 노드에 병합
		if (index == node->start + node->len) {
			struct tjournal_da_node *right = node->right;
			node->len++;

			// 오른쪽 노드와 병합 가능 여부
			if (right) {
				if (right->left) {
					struct tjournal_da_node *least, *prev;

					least = least_node(right, &prev);
					if (least != right &&
					    node->start + node->len - 1 ==
						    least->start) {
						node->len += least->len;
						prev->left = NULL;
						kfree(least);
						return;
					}
				}

				/* Direct merge with right node */
				if (node->start + node->len - 1 ==
				    right->start) {
					BUG_ON(right->left);
					node->len += right->len;
					node->right = right->right;
					kfree(right);
					return;
				}
			}
		}
		// 오른쪽 노드 생성
		else if (!node->right)
			node->right = create_da_node(index, 1);
		else
			__insert_da_node(node->right, index);
	}
}

static void __insert_da_journalled(struct tjournal_da_tree *tree, pgoff_t index)
{
	spin_lock(&tree->lock);
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

static struct tjournal_da_node *find_node(struct tjournal_da_node *node,
					  unsigned long index)
{
	if (!node)
		return NULL;

	/* Check this node contains the requested index */
	if (index >= node->start && index < node->start + node->len)
		return node;

	if (index < node->start)
		return find_node(node->left, index);

	return find_node(node->right, index);
}

static int __lookup_da_journalled(struct tjournal_da_tree *tree, pgoff_t index,
				  unsigned int *len)
{
	struct tjournal_da_node *node = NULL;

	spin_lock(&tree->lock);
	node = find_node(tree->root, index);
	spin_unlock(&tree->lock);

	if (!node)
		return 0;

	*len = node->start - index + node->len;
	tjk_debug("index(%lu) len(%u) done\n", index, *len);
	return 1;
}

/**
 * @brief Lookup delayed allocation state of file
 * 
 * @param len (extent length started from index)
 * @return 0: not found, 1: found
 */
int lookup_da_journalled(struct inode *inode, pgoff_t index, unsigned int *len)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	return __lookup_da_journalled(&ei->i_journalled_da_tree, index, len);
}

static int __truncate_da_journalled(struct tjournal_da_tree *tree,
				    pgoff_t start, unsigned int len)
{
	struct tjournal_da_node *node = NULL;
	pgoff_t end = start + len;
	int ret = 0;

	tjk_debug("start: %lu, len: %u\n", start, len);

	spin_lock(&tree->lock);
	node = find_node(tree->root, start);
	if (!node) {
		ret = -EINVAL;
		goto unlock;
	}

	/* completely contained by the node? */
	if (start < node->start || end > node->start + node->len) {
		ret = -EINVAL;
		goto unlock;
	}

	/* Split nodes context start */

	/* 1. We found exact matching node */
	if (start == node->start && len == node->len) {
		struct tjournal_da_node *parent = tree->root;
		struct tjournal_da_node **link = &tree->root;

		/* It is root node itself */
		if (parent == node) {
			if (node->left)
				tree->root = node->left;
			else
				tree->root = node->right;
			kfree(node);
			goto unlock;
		}

		/* Find the node iteratively */
		while (parent) {
			if (parent == node)
				break;

			if (start < parent->start) {
				link = &parent->left;
				parent = parent->left;
			} else {
				link = &parent->right;
				parent = parent->right;
			}
		}

		*link = (node->left) ? node->left : node->right;
		kfree(node);
		goto unlock;
	}

	if (start == node->start) {
		// 범위가 노드의 시작과 같음
		node->start = end;
		node->len -= len;
	} else if (end == node->start + node->len) {
		// 범위가 노드의 끝과 같음
		node->len -= len;
	} else {
		// 범위가 노드의 중간
		struct tjournal_da_node *new_node;

		new_node = create_da_node(end, node->start + node->len - end);
		if (!new_node) {
			ret = -ENOMEM;
			goto unlock;
		}
		new_node->left =
			node->right; // 기존 오른쪽 자식을 새 노드로 연결
		node->right =
			new_node; // 새 노드를 현재 노드의 오른쪽 자식으로 연결
		node->len = start - node->start; // 현재 노드 길이 수정
	}

unlock:
	spin_unlock(&tree->lock);
	return ret;
}

int truncate_da_journalled(struct inode *inode, pgoff_t start, unsigned int len)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	return __truncate_da_journalled(&ei->i_journalled_da_tree, start, len);
}