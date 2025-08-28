# 1. Trigger on block partitions (e.g., sdb1) when added
#/etc/udev/rules.d/99-scan-usb.rules

SUBSYSTEM=="block", KERNEL=="sd*[0-9]", ACTION=="add", ENV{ID_FS_TYPE}!="", RUN+="/usr/local/bin/scan-usb.sh %k"


# 2.
#/usr/local/bin/scan-usb.sh
#!/usr/bin/env bash
set -Eeuo pipefail

PART="$1"                       # e.g., sdb1
DEV="/dev/${PART}"
MNT="/mnt/usb-${PART}"
OUT="/var/log/usb-scans/${PART}-$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$MNT" "$OUT"

# 2. Mount read-only, safest flags
mount -o ro,nosuid,nodev,noexec "$DEV" "$MNT" || {
  echo "Mount failed for $DEV" >&2
  exit 1
}

# 3. Pull/build the scanner image first (do once): docker build -t usb-scanner:latest /opt/usb-scanner
docker run --rm \
  -v "$MNT":/scan:ro \
  -v "$OUT":/out \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /var/tmp:rw,noexec,nosuid,size=64m \
  --pids-limit 256 \
  usb-scanner:latest

umount "$MNT"
rmdir "$MNT"

echo "Scan complete. See $OUT"



#Third Step
cd /opt/usb-scanner
docker build -t usb-scanner:latest .

# 4. Dry run without udev (replace /media/me/USB with your mount):
docker run --rm \
  -v /media/me/USB:/scan:ro \
  -v "$PWD/out":/out \
  --network none --read-only \
  --tmpfs /tmp --tmpfs /var/tmp \
  --pids-limit 256 \
  usb-scanner:latest

# 5. See results:
ls -l out/
cat out/report.json | head
