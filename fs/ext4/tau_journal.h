#include "linux/page-flags.h"
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/pagemap.h>
#include <linux/jbd2.h>

#define TAU_CHECKPOINT_THRESHOLD 50 // percent

#define PG_GRAB_TXHANDLE \
	PG_private_2 /* Page bit for joining transaction (grab handles) */

static inline void folio_end_txhandle(struct folio *folio)
{
	folio_end_private_2(folio);
}

static inline int folio_test_grabtxhandle(struct folio *folio)
{
    return folio_test_private_2(folio);
}

static inline void folio_wait_txhandle(struct folio *folio)
{
	folio_wait_private_2(folio);
}

static inline void folio_set_grab_txhandle(struct folio *folio)
{
	folio_set_private_2(folio);
}

int tjournal_writepages(struct address_space *mapping);
void tjournal_init_inode(struct inode *);
bool tjournal_try_to_free_buffers(struct folio *);
int tjournal_start_thread(journal_t *);
int tjournal_need_checkpoint(journal_t *);

/* Delayed allocation */
void print_tjournal_da_tree_all(struct inode *);
void insert_da_journalled(struct inode *, pgoff_t index);
int lookup_da_journalled(struct inode *, pgoff_t *index, unsigned int *len);
int delete_da_journalled(struct inode *, pgoff_t start, unsigned int len);
bool has_da_journalled(struct inode *inode);
int truncate_da_journalled(struct inode *inode, pgoff_t start);

#define tj_warn(fmt, ...) printk(KERN_WARNING "     ↳ " fmt, ##__VA_ARGS__)

/* Debug option */
// #define TJOURNAL_COMMIT_DEBUG
// #define TJOURNAL_HANDLE_DEBUG
// #define TJOURNAL_DAEMON_DEBUG
// #define TJOURNAL_CHECKPOINT_DEBUG

#ifdef TJOURNAL_COMMIT_DEBUG
#define tjc_debug(f, a...)                                            \
	do {                                                          \
		printk(KERN_DEBUG "%s: (%s, %d)", __func__, __FILE__, \
		       __LINE__);                                     \
		printk(KERN_DEBUG "     ↳ " f, ##a);                  \
	} while (0)
#define tjc__debug(f, a...)                                  \
	do {                                                 \
		printk(KERN_DEBUG "     	↳ " f, ##a); \
	} while (0)
#else
#define tjc_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define tjc__debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#ifdef TJOURNAL_HANDLE_DEBUG
#define tjh_debug(f, a...)                                            \
	do {                                                          \
		printk(KERN_DEBUG "%s: (%s, %d)", __func__, __FILE__, \
		       __LINE__);                                     \
		printk(KERN_DEBUG "     ↳ " f, ##a);                  \
	} while (0)
#else
#define tjh_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#ifdef TJOURNAL_CHECKPOINT_DEBUG
#define tjk_debug(f, a...)                                            \
	do {                                                          \
		printk(KERN_DEBUG "%s: (%s, %d)", __func__, __FILE__, \
		       __LINE__);                                     \
		printk(KERN_DEBUG "     ↳ " f, ##a);                  \
	} while (0)
#else
#define tjk_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#ifdef TJOURNAL_DAEMON_DEBUG
#define tjd_debug(f, a...)                                            \
	do {                                                          \
		printk(KERN_DEBUG "%s: (%s, %d)", __func__, __FILE__, \
		       __LINE__);                                     \
		printk(KERN_DEBUG "     ↳ " f, ##a);                  \
	} while (0)
#else
#define tjd_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

/* Debug macros */
#if defined(TJOURNAL_COMMIT_DEBUG) || defined(TJOURNAL_HANDLE_DEBUG) || \
	defined(TJOURNAL_DAEMON_DEBUG) || defined(TJOURNAL_CHECKPOINT_DEBUG)

#define PRINT_INODE_INFO_COMPACT(inode)                                                           \
	do {                                                                                      \
		if (!inode) {                                                                     \
			pr_info("Invalid inode (NULL)\n");                                        \
			break;                                                                    \
		}                                                                                 \
		pr_debug(                                                                         \
			"     ↳ Inode(%lu): type=%s, mode=0%o, size=%llu, nlink=%u, dev=%u:%u\n", \
			inode->i_ino,                                                             \
			S_ISREG(inode->i_mode)	? "regular" :                                     \
			S_ISDIR(inode->i_mode)	? "dir" :                                         \
			S_ISCHR(inode->i_mode)	? "char_dev" :                                    \
			S_ISBLK(inode->i_mode)	? "block_dev" :                                   \
			S_ISFIFO(inode->i_mode) ? "fifo" :                                        \
			S_ISLNK(inode->i_mode)	? "symlink" :                                     \
			S_ISSOCK(inode->i_mode) ? "socket" :                                      \
						  "unknown",                                      \
			inode->i_mode, inode->i_size, inode->i_nlink,                             \
			MAJOR(inode->i_sb->s_dev), MINOR(inode->i_sb->s_dev));                    \
	} while (0)

#define PRINT_PAGE_FLAGS_COMPACT(page)                            \
	do {                                                      \
		if (!page) {                                      \
			pr_info("Invalid page: NULL\n");          \
			break;                                    \
		}                                                 \
		pr_info("Page index(%lu): [ ", page->index);      \
		if (PageLocked(page))                             \
			pr_cont("LOCK "); /* Locked */            \
		if (PageDirty(page))                              \
			pr_cont("DIRTY "); /* Dirty */            \
		if (PageUptodate(page))                           \
			pr_cont("UPTODATE "); /* Uptodate */      \
		if (PageWriteback(page))                          \
			pr_cont("WRITEBACK "); /* Writeback */    \
		if (PageMappedToDisk(page))                       \
			pr_cont("MAPPED "); /* MappedToDisk */    \
		if (PageSwapBacked(page))                         \
			pr_cont("SWAP "); /* SwapBacked */        \
		if (PageActive(page))                             \
			pr_cont("ACTIVE "); /* Active */          \
		if (PagePrivate2(page))                           \
			pr_cont("TXHANDLE "); /* In running Tx */ \
		pr_cont(" ] raw_ptr %p\n", page);                 \
	} while (0)
#define tj_debug(f, a...)                                    \
	do {                                                 \
		printk(KERN_DEBUG "     	↳ " f, ##a); \
	} while (0)
#else
#define PRINT_INODE_INFO_COMPACT(inode) no_printk("%p\n", inode)
#define PRINT_PAGE_FLAGS_COMPACT(page) no_printk("%p\n", page)
#define tj_debug(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

/**
 * print_bh_flags - Prints the flags of a given buffer_head.
 * @bh: Pointer to the buffer_head structure.
 *
 * This function prints all active flags of the buffer_head in a single line.
 */
static inline void print_bh_flags(struct buffer_head *bh)
{
	if (!bh) {
		printk(KERN_WARNING "buffer_head is NULL\n");
		return;
	}

	printk(KERN_INFO "BH_Flags bno(%lld):", bh->b_blocknr);

	/* Standard buffer_head flags */
	if (buffer_uptodate(bh))
		printk(KERN_CONT " BH_Uptodate");
	if (buffer_dirty(bh))
		printk(KERN_CONT " BH_Dirty");
	if (buffer_locked(bh))
		printk(KERN_CONT " BH_Lock");
	if (buffer_req(bh))
		printk(KERN_CONT " BH_Req");
	if (buffer_mapped(bh))
		printk(KERN_CONT " BH_Mapped");
	if (buffer_new(bh))
		printk(KERN_CONT " BH_New");
	if (buffer_async_write(bh))
		printk(KERN_CONT " BH_Async_Write");
	if (buffer_delay(bh))
		printk(KERN_CONT " BH_Delay");
	if (buffer_unwritten(bh))
		printk(KERN_CONT " BH_Unwritten");
	if (buffer_async_read(bh))
		printk(KERN_CONT " BH_Async_Read");
	if (buffer_meta(bh))
		printk(KERN_CONT " BH_Meta");
	if (buffer_prio(bh))
		printk(KERN_CONT " BH_Prio");
	if (buffer_defer_completion(bh))
		printk(KERN_CONT " BH_Defer_Completion");
	if (buffer_boundary(bh))
		printk(KERN_CONT " BH_Boundary");

	/* JBD-related buffer_head flags */
	if (buffer_jbd(bh))
		printk(KERN_CONT " BH_JBD");
	if (buffer_jwrite(bh))
		printk(KERN_CONT " BH_JWrite");
	if (buffer_freed(bh))
		printk(KERN_CONT " BH_Freed");
	if (buffer_revoked(bh))
		printk(KERN_CONT " BH_Revoked");
	if (buffer_revokevalid(bh))
		printk(KERN_CONT " BH_RevokeValid");
	if (buffer_jbddirty(bh))
		printk(KERN_CONT " BH_JBDDirty");
	if (buffer_shadow(bh))
		printk(KERN_CONT " BH_Shadow");
	if (buffer_verified(bh))
		printk(KERN_CONT " BH_Verified");

	printk(KERN_CONT "\n");
}
