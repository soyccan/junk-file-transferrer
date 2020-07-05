#!/bin/sh
if ! lsmod | grep ksocket >/dev/null 2>&1; then
    sudo insmod ksocket/src/ksocket.ko
fi

# if [ ! -e /dev/master_dev ]; then
#     sudo mknod /dev/master_dev c 64 0
# fi
# sudo chmod 666 /dev/master_dev

make master_dev master &&
    {
        sudo rmmod master_dev
        sudo insmod master_dev/master_dev.ko port=8888
    }
