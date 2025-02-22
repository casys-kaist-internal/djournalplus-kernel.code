// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include "linux/mm.h"
#include "linux/pagemap.h"
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include <linux/backing-dev.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "truncate.h"

/*
 * Returns %true if the given DIO request should be attempted with DIO, or
 * %false if it should fall back to buffered I/O.
 *
 * DIO isn't well specified; when it's unsupported (either due to the request
 * being misaligned, or due to the file not supporting DIO at all), filesystems
 * either fall back to buffered I/O or return EINVAL.  For files that don't use
 * any special features like encryption or verity, ext4 has traditionally
 * returned EINVAL for misaligned DIO.  iomap_dio_rw() uses this convention too.
 * In this case, we should attempt the DIO, *not* fall back to buffered I/O.
 *
 * In contrast, in cases where DIO is unsupported due to ext4 features, ext4
 * traditionally falls back to buffered I/O.
 *
 * This function implements the traditional ext4 behavior in all these cases.
 */
static bool ext4_should_use_dio(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	u32 dio_align = ext4_dio_alignment(inode);

	if (dio_align == 0)
		return false;

	if (dio_align == 1)
		return true;

	return IS_ALIGNED(iocb->ki_pos | iov_iter_alignment(iter), dio_align);
}

static ssize_t ext4_dio_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}

	if (!ext4_should_use_dio(iocb, to)) {
		inode_unlock_shared(inode);
		/*
		 * Fallback to buffered I/O if the operation being performed on
		 * the inode is not supported by direct I/O. The IOCB_DIRECT
		 * flag needs to be cleared here in order to ensure that the
		 * direct I/O path within generic_file_read_iter() is not
		 * taken.
		 */
		iocb->ki_flags &= ~IOCB_DIRECT;
		return generic_file_read_iter(iocb, to);
	}

	ret = iomap_dio_rw(iocb, to, &ext4_iomap_ops, NULL, 0, NULL, 0);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t ext4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_read_iter(iocb, to);
	}
	ret = dax_iomap_rw(iocb, to, &ext4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;
#ifdef CONFIG_EXT4_TAU_JOURNALING
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct tjournal_atomic_log *cur;
	loff_t offset = iocb->ki_pos, kdisp, udisp;
	size_t n, len = to->count;
#endif

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return ext4_dax_read_iter(iocb, to);
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_read_iter(iocb, to);

	ret = generic_file_read_iter(iocb, to);
#ifdef CONFIG_EXT4_TAU_JOURNALING
	if (ext4_test_inode_flag(inode, EXT4_STATE_ATOMIC_FILE)) {
		inode_lock_shared(inode);
		if (offset + len > inode->i_size && inode->i_size < ei->i_atomic_master.fsize) {
			n = min(ei->i_atomic_master.fsize, (size_t)offset + len) - max(inode->i_size, offset);
			if (clear_user(to->ubuf + ret, n)) {
				ret = -EFAULT;
				goto end_atomic_read;
			}
			ret += n;
		}
		cur = ei->i_atomic_master.head;
		while (cur) {
			// copy data to user space
			if (cur->offset + cur->len <= offset) {
				cur = cur->next;
				continue;
			}
			if (cur->offset >= offset + len)
				break;
			kdisp = cur->disp;
			udisp = 0;
			if (cur->offset < offset)
				kdisp += offset - cur->offset;
			else
				udisp = cur->offset - offset;
			n = min(cur->offset + cur->len, offset + len) - max(cur->offset, offset);
			if (copy_to_user(to->ubuf + udisp, (const char *)cur->data + kdisp, n)) {
				ret = -EFAULT;
				goto end_atomic_read;
			}
			cur = cur->next;
		}
end_atomic_read:
		inode_unlock_shared(inode);
	}
#endif
	return ret;
}

/*
 * Called when an inode is released. Note that this is different
 * from ext4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext4_release_file(struct inode *inode, struct file *filp)
{
	if (ext4_test_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE)) {
		ext4_alloc_da_blocks(inode);
		ext4_clear_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1) &&
			!EXT4_I(inode)->i_reserved_data_blocks) {
		down_write(&EXT4_I(inode)->i_data_sem);
		ext4_discard_preallocations(inode, 0);
		up_write(&EXT4_I(inode)->i_data_sem);
	}
	if (is_dx(inode) && filp->private_data)
		ext4_htree_free_dir_info(filp->private_data);

	return 0;
}

/*
 * This tests whether the IO in question is block-aligned or not.
 * Ext4 utilizes unwritten extents when hole-filling during direct IO, and they
 * are converted to written only after the IO is complete.  Until they are
 * mapped, these blocks appear as holes, so dio_zero_block() will assume that
 * it needs to zero out portions of the start and/or end block.  If 2 AIO
 * threads are at work on the same unwritten block, they must be synchronized
 * or one thread will zero the other's data, causing corruption.
 */
static bool
ext4_unaligned_io(struct inode *inode, struct iov_iter *from, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	unsigned long blockmask = sb->s_blocksize - 1;

	if ((pos | iov_iter_alignment(from)) & blockmask)
		return true;

	return false;
}

static bool
ext4_extending_io(struct inode *inode, loff_t offset, size_t len)
{
	if (offset + len > i_size_read(inode) ||
	    offset + len > EXT4_I(inode)->i_disksize)
		return true;
	return false;
}

/* Is IO overwriting allocated and initialized blocks? */
static bool ext4_overwrite_io(struct inode *inode, loff_t pos, loff_t len)
{
	struct ext4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = EXT4_MAX_BLOCKS(len, pos, blkbits);
	blklen = map.m_len;

	err = ext4_map_blocks(NULL, inode, &map, 0);
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. To exclude
	 * unwritten extents, we need to check m_flags.
	 */
	return err == blklen && (map.m_flags & EXT4_MAP_MAPPED);
}

static ssize_t ext4_generic_write_checks(struct kiocb *iocb,
					 struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}

	return iov_iter_count(from);
}

static ssize_t ext4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret, count;

	count = ext4_generic_write_checks(iocb, from);
	if (count <= 0)
		return count;

	ret = file_modified(iocb->ki_filp);
	if (ret)
		return ret;
	return count;
}

#ifdef CONFIG_EXT4_TAU_JOURNALING
/* based on generic_perform_write() */
static ssize_t ext4jp_perform_write(struct kiocb *iocb, struct iov_iter *i,
										struct page **pages, const void *data)
{
	struct file *file = iocb->ki_filp;
	loff_t pos = iocb->ki_pos;
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	int index = 0;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata = NULL;

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 */
		if (unlikely(!data && fault_in_iov_iter_readable(i, bytes) == bytes)) {
			status = -EFAULT;
			break;
		}

		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

		page = pages[index];
		lock_page(page);

		status = a_ops->write_begin(file, mapping, pos, bytes,
						&page, &fsdata);
		if (unlikely(status < 0)) {
			unlock_page(page);
			put_page(page);
			break;
		}

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		if (data)
			copied = copy_page_from_iter_atomic_kern(page, offset, bytes, i, data);
		else
			copied = copy_page_from_iter_atomic(page, offset, bytes, i);
		flush_dcache_page(page);

		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status != copied)) {
			iov_iter_revert(i, copied - max(status, 0L));
			if (unlikely(status < 0))
				break;
		}
		cond_resched();

		if (unlikely(status == 0)) {
			/*
			 * A short copy made ->write_end() reject the
			 * thing entirely.  Might be memory poisoning
			 * halfway through, might be a race with munmap,
			 * might be severe memory pressure.
			 */
			if (copied)
				bytes = copied;
			goto again;
		}
		pos += status;
		written += status;

		balance_dirty_pages_ratelimited(mapping);
		index++;
	} while (iov_iter_count(i));

	return written ? written : status;
}

/**
 * @brief For multi-block atomic write, start handle outside perform_write
 * 
 * @note inode_lock is held by caller
 */
static ssize_t ext4jp_buffered_write_iter(struct kiocb *iocb,
					struct iov_iter *from, struct inode *inode)
{
	struct page **pages;
	handle_t *handle = NULL;
	ssize_t ret;
	int needed_blocks, nr_blks;
	unsigned int block_size;
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct tjournal_atomic_log *cur, *new = NULL, *prev = NULL, *tmp;
	loff_t offset = iocb->ki_pos;
	size_t len = from->count;

	if (ext4_test_inode_flag(inode, EXT4_STATE_ATOMIC_FILE)) {
		cur = ei->i_atomic_master.head;
		while (cur) {
			// traverse and remove overlap logs
			if (cur->offset + cur->len <= offset) {
				prev = cur;
				cur = cur->next;
				continue;
			}
			if (cur->offset >= offset + len) {
				break;
			}
			if (cur->offset <= offset && cur->offset + cur->len >= offset + len) {
				BUG_ON(new);
				if (copy_from_user(cur->data + cur->disp + offset - cur->offset, from->ubuf, len))
					return -EFAULT;
				return len;
			}
			if (!new) {
				new = kmalloc(sizeof(struct tjournal_atomic_log), GFP_KERNEL);
				if (new == NULL)
					return -ENOMEM;
				new->data = kmalloc(len, GFP_KERNEL);
				if (new->data == NULL) {
					kfree(new);
					return -ENOMEM;
				}
				new->disp = 0;
				new->offset = offset;
				new->len = len;
				if (copy_from_user(new->data, from->ubuf, len)) {
					kfree(new->data);
					kfree(new);
					return -EFAULT;
				}
			}
			if (cur->offset + cur->len <= offset + len) {
				if (cur->offset >= offset) {
					tmp = cur;
					cur = cur->next;
					if (prev)
						prev->next = cur;
					else
						ei->i_atomic_master.head = cur;
					kfree(tmp->data);
					kfree(tmp);
					continue;
				}
				else {
					cur->len = offset - cur->offset;
					prev = cur;
					cur = cur->next;
					continue;
				}
			}
			cur->disp += offset + len - cur->offset;
			cur->len -= offset + len - cur->offset;
			cur->offset = offset + len;
			break;
		}
		if (!new) {
			new = kmalloc(sizeof(struct tjournal_atomic_log), GFP_KERNEL);
			if (new == NULL)
				return -ENOMEM;
			new->data = kmalloc(len, GFP_KERNEL);
			if (new->data == NULL) {
				kfree(new);
				return -ENOMEM;
			}
			new->disp = 0;
			new->offset = offset;
			new->len = len;
			if (copy_from_user(new->data, from->ubuf, len)) {
				kfree(new->data);
				kfree(new);
				return -EFAULT;
			}
		}
		if (prev) {
			BUG_ON(prev->next != cur);
			new->next = cur;
			prev->next = new;
		}
		else {
			BUG_ON(ei->i_atomic_master.head != cur);
			new->next = ei->i_atomic_master.head;
			ei->i_atomic_master.head = new;
		}
		if (offset + len > ei->i_atomic_master.fsize)
			ei->i_atomic_master.fsize = offset + len;
		return len;
	}

	/* Total data blocks */
	block_size =  1 << inode->i_sb->s_blocksize_bits;
	nr_blks = (iocb->ki_pos % block_size + from->count + block_size - 1) / block_size;

	/* Grab pages first in batch w/o locking */
	pages = ext4jp_prepare_pages(inode, iocb, nr_blks);
	if (!pages)
		return -ENOMEM;

	/* Data blocks + some metadata blocks */
	needed_blocks = nr_blks +  EXT4_META_TRANS_BLOCKS(inode->i_sb);

	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	current->backing_dev_info = inode_to_bdi(inode);
	ret = ext4jp_perform_write(iocb, from, pages, NULL);
	current->backing_dev_info = NULL;

#ifdef EXT4_JP_ALLOC_ON_COMMIT
	if (nr_append) /* We did dealloc some block. */
		ext4jp_alloc_on_commit_or_stop(handle, inode);
	else /* We did not dealloc any block. */
		ext4_journal_stop(handle);
#endif

	ext4_journal_stop(handle);
	kfree(pages);
	return ret;
}

ssize_t ext4jp_write_atomic_log(struct file *filep, loff_t offset, const void *data, size_t size) {
	struct inode *inode = filep->f_inode;
	struct page **pages;
	ssize_t ret;
	int nr_blks;
	unsigned int block_size;
	struct kiocb iocb;
	struct iov_iter from;

	init_sync_kiocb(&iocb, filep);
	iocb.ki_pos = offset;
	iov_iter_ubuf(&from, ITER_SOURCE, (void __user *)NULL, size);

	/* Total data blocks */
	block_size =  1 << inode->i_sb->s_blocksize_bits;
	nr_blks = (offset % block_size + size + block_size - 1) / block_size;

	/* Grab pages first in batch w/o locking */
	pages = ext4jp_prepare_pages(inode, &iocb, nr_blks);
	if (!pages)
		return -ENOMEM;

	current->backing_dev_info = inode_to_bdi(inode);
	ret = ext4jp_perform_write(&iocb, &from, pages, data);
	current->backing_dev_info = NULL;

#ifdef EXT4_JP_ALLOC_ON_COMMIT
	// We do not consider alloc on commit for now.
	BUG();
#endif

	kfree(pages);
	if (likely(ret > 0)) {
		iocb.ki_pos += ret;
		ret = generic_write_sync(&iocb, ret);
	}
	return ret;
}

#endif /* CONFIG_EXT4_TAU_JOURNALING */

static ssize_t ext4_buffered_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	inode_lock(inode);
	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

#ifdef CONFIG_EXT4_TAU_JOURNALING
	/* TODO: We need to separated tau-mode & normal mode */
	if (ext4_should_journal_plus(inode)) {
		ret = ext4jp_buffered_write_iter(iocb, from, inode);
		goto out;
	}
#endif

	current->backing_dev_info = inode_to_bdi(inode);
	ret = generic_perform_write(iocb, from);
	current->backing_dev_info = NULL;

out:
	inode_unlock(inode);
	if (likely(ret > 0)) {
		iocb->ki_pos += ret;
		ret = generic_write_sync(iocb, ret);
	}

	return ret;
}

static ssize_t ext4_handle_inode_extension(struct inode *inode, loff_t offset,
					   ssize_t written, size_t count)
{
	handle_t *handle;
	bool truncate = false;
	u8 blkbits = inode->i_blkbits;
	ext4_lblk_t written_blk, end_blk;
	int ret;

	/*
	 * Note that EXT4_I(inode)->i_disksize can get extended up to
	 * inode->i_size while the I/O was running due to writeback of delalloc
	 * blocks. But, the code in ext4_iomap_alloc() is careful to use
	 * zeroed/unwritten extents if this is possible; thus we won't leave
	 * uninitialized blocks in a file even if we didn't succeed in writing
	 * as much as we intended.
	 */
	WARN_ON_ONCE(i_size_read(inode) < EXT4_I(inode)->i_disksize);
	if (offset + count <= EXT4_I(inode)->i_disksize) {
		/*
		 * We need to ensure that the inode is removed from the orphan
		 * list if it has been added prematurely, due to writeback of
		 * delalloc blocks.
		 */
		if (!list_empty(&EXT4_I(inode)->i_orphan) && inode->i_nlink) {
			handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);

			if (IS_ERR(handle)) {
				ext4_orphan_del(NULL, inode);
				return PTR_ERR(handle);
			}

			ext4_orphan_del(handle, inode);
			ext4_journal_stop(handle);
		}

		return written;
	}

	if (written < 0)
		goto truncate;

	handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
	if (IS_ERR(handle)) {
		written = PTR_ERR(handle);
		goto truncate;
	}

	if (ext4_update_inode_size(inode, offset + written)) {
		ret = ext4_mark_inode_dirty(handle, inode);
		if (unlikely(ret)) {
			written = ret;
			ext4_journal_stop(handle);
			goto truncate;
		}
	}

	/*
	 * We may need to truncate allocated but not written blocks beyond EOF.
	 */
	written_blk = ALIGN(offset + written, 1 << blkbits);
	end_blk = ALIGN(offset + count, 1 << blkbits);
	if (written_blk < end_blk && ext4_can_truncate(inode))
		truncate = true;

	/*
	 * Remove the inode from the orphan list if it has been extended and
	 * everything went OK.
	 */
	if (!truncate && inode->i_nlink)
		ext4_orphan_del(handle, inode);
	ext4_journal_stop(handle);

	if (truncate) {
truncate:
		ext4_truncate_failed_write(inode);
		/*
		 * If the truncate operation failed early, then the inode may
		 * still be on the orphan list. In that case, we need to try
		 * remove the inode from the in-memory linked list.
		 */
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}

	return written;
}

static int ext4_dio_write_end_io(struct kiocb *iocb, ssize_t size,
				 int error, unsigned int flags)
{
	loff_t pos = iocb->ki_pos;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (error)
		return error;

	if (size && flags & IOMAP_DIO_UNWRITTEN) {
		error = ext4_convert_unwritten_extents(NULL, inode, pos, size);
		if (error < 0)
			return error;
	}
	/*
	 * If we are extending the file, we have to update i_size here before
	 * page cache gets invalidated in iomap_dio_rw(). Otherwise racing
	 * buffered reads could zero out too much from page cache pages. Update
	 * of on-disk size will happen later in ext4_dio_write_iter() where
	 * we have enough information to also perform orphan list handling etc.
	 * Note that we perform all extending writes synchronously under
	 * i_rwsem held exclusively so i_size update is safe here in that case.
	 * If the write was not extending, we cannot see pos > i_size here
	 * because operations reducing i_size like truncate wait for all
	 * outstanding DIO before updating i_size.
	 */
	pos += size;
	if (pos > i_size_read(inode))
		i_size_write(inode, pos);

	return 0;
}

static const struct iomap_dio_ops ext4_dio_write_ops = {
	.end_io = ext4_dio_write_end_io,
};

/*
 * The intention here is to start with shared lock acquired then see if any
 * condition requires an exclusive inode lock. If yes, then we restart the
 * whole operation by releasing the shared lock and acquiring exclusive lock.
 *
 * - For unaligned_io we never take shared lock as it may cause data corruption
 *   when two unaligned IO tries to modify the same block e.g. while zeroing.
 *
 * - For extending writes case we don't take the shared lock, since it requires
 *   updating inode i_disksize and/or orphan handling with exclusive lock.
 *
 * - shared locking will only be true mostly with overwrites. Otherwise we will
 *   switch to exclusive i_rwsem lock.
 */
static ssize_t ext4_dio_write_checks(struct kiocb *iocb, struct iov_iter *from,
				     bool *ilock_shared, bool *extend)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	loff_t offset;
	size_t count;
	ssize_t ret;

restart:
	ret = ext4_generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	count = ret;
	if (ext4_extending_io(inode, offset, count))
		*extend = true;
	/*
	 * Determine whether the IO operation will overwrite allocated
	 * and initialized blocks.
	 * We need exclusive i_rwsem for changing security info
	 * in file_modified().
	 */
	if (*ilock_shared && (!IS_NOSEC(inode) || *extend ||
	     !ext4_overwrite_io(inode, offset, count))) {
		if (iocb->ki_flags & IOCB_NOWAIT) {
			ret = -EAGAIN;
			goto out;
		}
		inode_unlock_shared(inode);
		*ilock_shared = false;
		inode_lock(inode);
		goto restart;
	}

	ret = file_modified(file);
	if (ret < 0)
		goto out;

	return count;
out:
	if (*ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
	return ret;
}

static ssize_t ext4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	handle_t *handle;
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	const struct iomap_ops *iomap_ops = &ext4_iomap_ops;
	bool extend = false, unaligned_io = false;
	bool ilock_shared = true;

	/*
	 * We initially start with shared inode lock unless it is
	 * unaligned IO which needs exclusive lock anyways.
	 */
	if (ext4_unaligned_io(inode, from, offset)) {
		unaligned_io = true;
		ilock_shared = false;
	}
	/*
	 * Quick check here without any i_rwsem lock to see if it is extending
	 * IO. A more reliable check is done in ext4_dio_write_checks() with
	 * proper locking in place.
	 */
	if (offset + count > i_size_read(inode))
		ilock_shared = false;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (ilock_shared) {
			if (!inode_trylock_shared(inode))
				return -EAGAIN;
		} else {
			if (!inode_trylock(inode))
				return -EAGAIN;
		}
	} else {
		if (ilock_shared)
			inode_lock_shared(inode);
		else
			inode_lock(inode);
	}

	/* Fallback to buffered I/O if the inode does not support direct I/O. */
	if (!ext4_should_use_dio(iocb, from)) {
		if (ilock_shared)
			inode_unlock_shared(inode);
		else
			inode_unlock(inode);
		return ext4_buffered_write_iter(iocb, from);
	}

	ret = ext4_dio_write_checks(iocb, from, &ilock_shared, &extend);
	if (ret <= 0)
		return ret;

	/* if we're going to block and IOCB_NOWAIT is set, return -EAGAIN */
	if ((iocb->ki_flags & IOCB_NOWAIT) && (unaligned_io || extend)) {
		ret = -EAGAIN;
		goto out;
	}
	/*
	 * Make sure inline data cannot be created anymore since we are going
	 * to allocate blocks for DIO. We know the inode does not have any
	 * inline data now because ext4_dio_supported() checked for that.
	 */
	ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);

	offset = iocb->ki_pos;
	count = ret;

	/*
	 * Unaligned direct IO must be serialized among each other as zeroing
	 * of partial blocks of two competing unaligned IOs can result in data
	 * corruption.
	 *
	 * So we make sure we don't allow any unaligned IO in flight.
	 * For IOs where we need not wait (like unaligned non-AIO DIO),
	 * below inode_dio_wait() may anyway become a no-op, since we start
	 * with exclusive lock.
	 */
	if (unaligned_io)
		inode_dio_wait(inode);

	if (extend) {
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		ret = ext4_orphan_add(handle, inode);
		if (ret) {
			ext4_journal_stop(handle);
			goto out;
		}

		ext4_journal_stop(handle);
	}

	if (ilock_shared)
		iomap_ops = &ext4_iomap_overwrite_ops;
	ret = iomap_dio_rw(iocb, from, iomap_ops, &ext4_dio_write_ops,
			   (unaligned_io || extend) ? IOMAP_DIO_FORCE_WAIT : 0,
			   NULL, 0);
	if (ret == -ENOTBLK)
		ret = 0;

	if (extend)
		ret = ext4_handle_inode_extension(inode, offset, ret, count);

out:
	if (ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);

	if (ret >= 0 && iov_iter_count(from)) {
		ssize_t err;
		loff_t endbyte;

		offset = iocb->ki_pos;
		err = ext4_buffered_write_iter(iocb, from);
		if (err < 0)
			return err;

		/*
		 * We need to ensure that the pages within the page cache for
		 * the range covered by this I/O are written to disk and
		 * invalidated. This is in attempt to preserve the expected
		 * direct I/O semantics in the case we fallback to buffered I/O
		 * to complete off the I/O request.
		 */
		ret += err;
		endbyte = offset + err - 1;
		err = filemap_write_and_wait_range(iocb->ki_filp->f_mapping,
						   offset, endbyte);
		if (!err)
			invalidate_mapping_pages(iocb->ki_filp->f_mapping,
						 offset >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
	}

	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t
ext4_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	size_t count;
	loff_t offset;
	handle_t *handle;
	bool extend = false;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode))
			return -EAGAIN;
	} else {
		inode_lock(inode);
	}

	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	count = iov_iter_count(from);

	if (offset + count > EXT4_I(inode)->i_disksize) {
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}

		ret = ext4_orphan_add(handle, inode);
		if (ret) {
			ext4_journal_stop(handle);
			goto out;
		}

		extend = true;
		ext4_journal_stop(handle);
	}

	ret = dax_iomap_rw(iocb, from, &ext4_iomap_ops);

	if (extend)
		ret = ext4_handle_inode_extension(inode, offset, ret, count);
out:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
#endif

static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return ext4_dax_write_iter(iocb, from);
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_write_iter(iocb, from);
	else
		return ext4_buffered_write_iter(iocb, from);
}

#ifdef CONFIG_FS_DAX
static vm_fault_t ext4_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	int error = 0;
	vm_fault_t result;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for pe_size != PE_SIZE_PTE (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		filemap_invalidate_lock_shared(mapping);
retry:
		handle = ext4_journal_start_sb(sb, EXT4_HT_WRITE_PAGE,
					       EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			filemap_invalidate_unlock_shared(mapping);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		filemap_invalidate_lock_shared(mapping);
	}
	result = dax_iomap_fault(vmf, pe_size, &pfn, &error, &ext4_iomap_ops);
	if (write) {
		ext4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    ext4_should_retry_alloc(sb, &retries))
			goto retry;
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, pe_size, pfn);
		filemap_invalidate_unlock_shared(mapping);
		sb_end_pagefault(sb);
	} else {
		filemap_invalidate_unlock_shared(mapping);
	}

	return result;
}

static vm_fault_t ext4_dax_fault(struct vm_fault *vmf)
{
	return ext4_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct ext4_dax_vm_ops = {
	.fault		= ext4_dax_fault,
	.huge_fault	= ext4_dax_huge_fault,
	.page_mkwrite	= ext4_dax_fault,
	.pfn_mkwrite	= ext4_dax_fault,
};
#else
#define ext4_dax_vm_ops	ext4_file_vm_ops
#endif

static const struct vm_operations_struct ext4_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = ext4_page_mkwrite,
};

static int ext4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct dax_device *dax_dev = sbi->s_daxdev;

	if (unlikely(ext4_forced_shutdown(sbi)))
		return -EIO;

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, dax_dev))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &ext4_dax_vm_ops;
		vma->vm_flags |= VM_HUGEPAGE;
	} else {
		vma->vm_ops = &ext4_file_vm_ops;
	}
	return 0;
}

static int ext4_sample_last_mounted(struct super_block *sb,
				    struct vfsmount *mnt)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct path path;
	char buf[64], *cp;
	handle_t *handle;
	int err;

	if (likely(ext4_test_mount_flag(sb, EXT4_MF_MNTDIR_SAMPLED)))
		return 0;

	if (sb_rdonly(sb) || !sb_start_intwrite_trylock(sb))
		return 0;

	ext4_set_mount_flag(sb, EXT4_MF_MNTDIR_SAMPLED);
	/*
	 * Sample where the filesystem has been mounted and
	 * store it in the superblock for sysadmin convenience
	 * when trying to sort through large numbers of block
	 * devices or filesystem images.
	 */
	memset(buf, 0, sizeof(buf));
	path.mnt = mnt;
	path.dentry = mnt->mnt_root;
	cp = d_path(&path, buf, sizeof(buf));
	err = 0;
	if (IS_ERR(cp))
		goto out;

	handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
	err = PTR_ERR(handle);
	if (IS_ERR(handle))
		goto out;
	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = ext4_journal_get_write_access(handle, sb, sbi->s_sbh,
					    EXT4_JTR_NONE);
	if (err)
		goto out_journal;
	lock_buffer(sbi->s_sbh);
	strncpy(sbi->s_es->s_last_mounted, cp,
		sizeof(sbi->s_es->s_last_mounted));
	ext4_superblock_csum_set(sb);
	unlock_buffer(sbi->s_sbh);
	ext4_handle_dirty_metadata(handle, NULL, sbi->s_sbh);
out_journal:
	ext4_journal_stop(handle);
out:
	sb_end_intwrite(sb);
	return err;
}

static int ext4_file_open(struct inode *inode, struct file *filp)
{
	int ret;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	ret = ext4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	ret = fscrypt_file_open(inode, filp);
	if (ret)
		return ret;

	ret = fsverity_file_open(inode, filp);
	if (ret)
		return ret;

	/*
	 * Set up the jbd2_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	filp->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC;
	return dquot_file_open(inode, filp);
}

/*
 * ext4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t ext4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		maxbytes = EXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	default:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_HOLE:
		inode_lock_shared(inode);
		offset = iomap_seek_hole(inode, offset,
					 &ext4_iomap_report_ops);
		inode_unlock_shared(inode);
		break;
	case SEEK_DATA:
		inode_lock_shared(inode);
		offset = iomap_seek_data(inode, offset,
					 &ext4_iomap_report_ops);
		inode_unlock_shared(inode);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, maxbytes);
}

const struct file_operations ext4_file_operations = {
	.llseek		= ext4_llseek,
	.read_iter	= ext4_file_read_iter,
	.write_iter	= ext4_file_write_iter,
	.iopoll		= iocb_bio_iopoll,
	.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext4_compat_ioctl,
#endif
	.mmap		= ext4_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= ext4_file_open,
	.release	= ext4_release_file,
	.fsync		= ext4_sync_file,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= ext4_fallocate,
};

const struct inode_operations ext4_file_inode_operations = {
	.setattr	= ext4_setattr,
	.getattr	= ext4_file_getattr,
	.listxattr	= ext4_listxattr,
	.get_inode_acl	= ext4_get_acl,
	.set_acl	= ext4_set_acl,
	.fiemap		= ext4_fiemap,
	.fileattr_get	= ext4_fileattr_get,
	.fileattr_set	= ext4_fileattr_set,
};

