#!/bin/sh
# TEST LAB ONLY.
set -e

# Local ClamAV signature: MD5 of the planted webshell, so clamscan works without
# downloading the full signature database. Format: md5:size:name
SHELL_FILE=/var/www/site/wp-content/uploads/2026/09/cache.php
# Only (re)write the signature while the sample exists; a restart after the sample was
# quarantined must not replace a valid signature with an empty one.
if [ -f "$SHELL_FILE" ]; then
  echo "$(md5sum "$SHELL_FILE" | cut -d' ' -f1):$(stat -c %s "$SHELL_FILE"):Lab.Php.Webshell" > /var/lib/clamav/lab.hdb
fi

# Fake "crypto-miner": just sleep, renamed and started from /tmp.
cp /bin/sleep /tmp/xmrig
su ops -c "/tmp/xmrig 100000 &"

su ops -c "python3 /opt/lab/server.py &"
exec /usr/sbin/sshd -D -e
