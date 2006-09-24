#!/bin/sh
ulimit -c unlimited
echo "Start date: `date`"
#ZFS_DEBUG=on /usr/bin/time -v nice -n 20 ./ztest -V -T 86400 &> log.txt
#/usr/bin/time -v nice -n 20 ./ztest -V -T 86400
nice -n 20 ./ztest -V $* && echo Test successful
echo "End date: `date`"
