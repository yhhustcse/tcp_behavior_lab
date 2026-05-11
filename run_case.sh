#!/usr/bin/env bash
set -u

payload="${1:-}"
if [ -z "$payload" ]; then
  echo "Usage: $0 <payload.bin>"
  exit 1
fi

if [ ! -f "./recovered_sample" ]; then
  echo "[ERROR] current directory does not contain ./recovered_sample"
  echo "        Copy the reassembled binary here or rename it to recovered_sample."
  exit 1
fi

if [ ! -f "$payload" ]; then
  echo "[ERROR] payload not found: $payload"
  exit 1
fi

if ! command -v qemu-i386 >/dev/null 2>&1; then
  echo "[ERROR] qemu-i386 not found. Install qemu-user/qemu-user-static first."
  exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
  echo "[ERROR] nc not found. Install netcat-openbsd first."
  exit 1
fi

rm -f trace.log qemu_syscall.log sample_stdout.log
chmod +x recovered_sample

timeout 15s qemu-i386 -strace -d in_asm -D trace.log ./recovered_sample >sample_stdout.log 2>qemu_syscall.log &
qemu_pid=$!

sleep 1
cat "$payload" | nc -q 1 127.0.0.1 12345 || true
wait "$qemu_pid" || true

echo
echo "========== payload =========="
echo "$payload"
xxd -g1 -l 120 "$payload" 2>/dev/null || true

echo
echo "========== sample_stdout.log =========="
cat sample_stdout.log 2>/dev/null || true

echo
echo "========== qemu_syscall.log tail =========="
tail -n 100 qemu_syscall.log 2>/dev/null || true

echo
echo "========== key evidence =========="
grep -Ei "double|free|corrupt|abort|segv|sig|mprotect|overflow|out-of-bounds|count|alloc_size|setenforce|SELinux|nc -l|54321|auth.log|system.sh|fork|clone" \
  sample_stdout.log qemu_syscall.log trace.log 2>/dev/null | tail -n 120 || true
