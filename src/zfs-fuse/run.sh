#!/bin/sh

ulimit -c unlimited

./zfs-fuse --no-daemon
