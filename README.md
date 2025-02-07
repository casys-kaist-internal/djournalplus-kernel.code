Linux for TAU-journalig file system
============

This kernel is based on 6.8.0 version of linux.
Supports TAU-journaling mode of ext4 file system
TAU-journaling is advanced data journaling mode.
 - Reduce write amplification by maintaining large journal area.
 - Increase performance by reaping out intervention of writeback.
 - Support delayed allocation while using data journaling mode.
 - (TODO) If App wants ordered mode, provide different mode for them.

### Build
You can use TAU-journaling by enabling EXT4_TAU_JOUNRALI
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
sudo mount -o data=journal,tjournal /dev/nvmeX {Mountpoint}
```

### Update 2025-02-06
Now we update kernel version to 6.8.0 from 6.2.10
There are some updates in new kernel (e.g. folio update in ext4)
