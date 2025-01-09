Linux kernel
============

There are several guides for kernel developers and users. These guides can
be rendered in a number of formats, like HTML and PDF. Please read
Documentation/admin-guide/README.rst first.

In order to build the documentation, use ``make htmldocs`` or
``make pdfdocs``.  The formatted documentation can also be read online at:

    https://www.kernel.org/doc/html/latest/

There are various text files in the Documentation/ subdirectory,
several of them using the Restructured Text markup notation.

Please read the Documentation/process/changes.rst file, as it contains the
requirements for building and running the kernel, and information about
the problems which may result by upgrading your kernel.

## Linux for TAU-journalig file system

This kernel is based on 6.2.0 version of linux.
Supports TAU-journaling mode of ext4 file system
TAU-journaling is advanced data journaling mode.
 - Reduce write amplification by maintaining large journal area.
 - Increase performance by reaping out intervention of writeback.
 - Support delayed allocation while using data journaling mode.
 - (TODO) If App wants ordered mode, provide different mode for them.

For now, DJPLUS or data journal plus naming were used.
It will be modified later, integrated as TAU-journal or tjournal.

### Build
You can use TAU-journaling by enabling EXT4_TAU_JOUNRALING
This is default on this repository
```shell
make menuconfig
make -j
sudo make install
```

### MKFS
[Important]
Disable lazy init option of inode table and journal.
If you do not handle this, you may have problem when you umount.
It will be fixed later.
```shell
sudo mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 /dev/nvmeX
```

### Mount
Mount option is below, use with data=journal together.
Do not disable delayed allocation when using tau-journaling.
```shell
sudo mount -o data=journal,data_journal_plus /dev/nvmeX {Mountpoint}
```
