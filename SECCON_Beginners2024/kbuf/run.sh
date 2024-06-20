#!/bin/sh
set -e

musl-gcc exploit.c -o exploit -static
mv exploit root
cd root; find . -print0 | cpio -o --null --owner=root --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
     -m 64M \
     -nographic \
     -kernel bzImage \
     -initrd debugfs.cpio \
     -drive file=flag.txt,format=raw \
     -snapshot \
     -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr root=/dev/sda" \
     -no-reboot \
     -cpu qemu64,+smap,+smep \
     -monitor /dev/null \
     -net nic,model=virtio \
     -net user \
     -gdb tcp::12345
