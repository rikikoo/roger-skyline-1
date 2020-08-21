#!/bin/bash

# This super simple "script" updates all installed packages.
# The process is logged to a file located in /var/log/update_script.log.

date >> /var/log/update_script.log && \
apt-get update -y >> /var/log/update_script.log && \
apt-get upgrade -y >> /var/log/update_script.log
