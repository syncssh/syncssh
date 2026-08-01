#!/bin/bash
set -e

# Set root password from env (falls back to a default for dev convenience)
echo "root:${VPS_ROOT_PASSWORD:-syncssh}" | chpasswd

service cron start

exec /usr/sbin/sshd -D
