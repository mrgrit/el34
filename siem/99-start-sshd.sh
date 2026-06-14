#!/usr/bin/with-contenv bash
# wazuh cont-init.d 마지막에 sshd daemon 띄움. wazuh services 와 무관.
echo '[cont-init.d/99] starting sshd (background daemon)'
/usr/sbin/sshd -D -e > /var/log/sshd.log 2>&1 &
echo "[cont-init.d/99] sshd pid=$!"
exit 0
