#!/bin/bash
# run.sh — Lance la VM victime (disk.qcow2)

DISK="$(dirname "$(realpath "$0")")/disk.qcow2"

if [ ! -f "$DISK" ]; then
    echo "[-] disk.qcow2 introuvable. Lance ./command.sh d'abord."
    exit 1
fi

echo "[*] VM — Ctrl+A puis X pour quitter"
echo "[*] Host C2 joignable sur : 10.0.0.1:4444"
echo ""

qemu-system-x86_64 \
    -drive file="$DISK",format=qcow2 \
    -m 2G \
    -nographic \
    -enable-kvm \
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
    -device e1000,netdev=net0
