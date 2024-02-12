#!/bin/sh

RAMFS_DIR="./ramfs"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] please run as root"
    exit 1
fi

# try to unmount the ramfs
umount $RAMFS_DIR 2>/dev/null

# remove the ramfs directory
rm -rf $RAMFS_DIR

# create the ramfs directory
mkdir $RAMFS_DIR

# mount the ramfs
mount -t ramfs -o size=200m ramfs $RAMFS_DIR

# show error and close if the mount failed
if [ $? -ne 0 ]; then
    echo "[-] failed to mount ramfs"
    exit 1
fi

# create a file in the ramfs
echo "hello world" > $RAMFS_DIR/hello.txt

# show error and close if the file creation failed
if [ $? -ne 0 ]; then
    echo "[-] failed to create file"
    exit 1
fi

# delete the file
rm $RAMFS_DIR/hello.txt

# set permissions for everyone
chmod -R 777 $RAMFS_DIR
