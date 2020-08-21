#!/bin/bash

md5sum /etc/crontab > /etc/croncheck.txt
diff /etc/croncheck.txt /etc/md5cron.txt > /dev/null 2>&1
error=$?
if [ $error -eq 1 ]
then
	echo "crontab was modified in the last 24h." | mail -s "cron report" root@localhost
fi
