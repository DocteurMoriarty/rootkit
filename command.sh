#!/bin/bash
set -e

# ─── CONFIG ───────────────────────────────────────────────────────────────────
DISK_IMG="../disk.img"
ROOTFS="/tmp/my-rootfs"
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$PROJ_DIR/linux-6.19.9/arch/x86/boot"   # adapte ce chemin si besoin
KERNEL="$KERNEL_DIR/bzImage"   # adapte ce chemin si besoin
RK_BIN_NAME=$(cat "$PROJ_DIR/rootkit_module/.rk_bin_name" 2>/dev/null || echo "")
RK_KO_NAME=$(cat "$PROJ_DIR/rootkit_module/.rk_name" 2>/dev/null || echo "")
COMPANION_BIN="$PROJ_DIR/rootkit_module/$RK_BIN_NAME"
# ──────────────────────────────────────────────────────────────────────────────


ROOT_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
# -----------------------------------------------------------------------------

echo "[0/13] Configuration générée :"
echo "    → Root Password : $ROOT_PASS"
echo "    → User Password : $USER_PASS"


echo "[1/12] Nettoyage..."
sudo umount "$ROOTFS" 2>/dev/null || true
sudo losetup -j "$DISK_IMG" | awk -F: '{print $1}' | xargs -r sudo losetup -d 2>/dev/null || true
rm -f "$DISK_IMG"
rm -f disk.qcow2
mkdir -p "$ROOTFS"

echo "[2/12] Création de l'image disque..."
truncate -s 2000M "$DISK_IMG"
/sbin/parted -s "$DISK_IMG" mktable msdos
/sbin/parted -s "$DISK_IMG" mkpart primary ext4 1MiB "100%"
/sbin/parted -s "$DISK_IMG" set 1 boot on

echo "[3/12] Attachement loop..."
LOOP=$(sudo losetup -Pf --show "$DISK_IMG")
echo "    → Loop device : $LOOP"

echo "[4/12] Formatage de la partition..."
sudo mkfs.ext4 "${LOOP}p1"

echo "[5/12] Montage..."
sudo mount "${LOOP}p1" "$ROOTFS"

echo "[6/12] Peuplement via Docker (Alpine)..."
sudo docker run --rm -v "$ROOTFS":/my-rootfs alpine sh -c "
    apk add openrc util-linux build-base musl-dev clang llvm bpftool libbpf-dev linux-headers tmux openssh &&
    ln -s agetty /etc/init.d/agetty.ttyS0 &&
    echo ttyS0 > /etc/securetty &&
    mkdir -p /etc/runlevels/boot /etc/runlevels/default &&
    ln -sf /etc/init.d/agetty.ttyS0 /etc/runlevels/default/agetty.ttyS0 &&
    ln -sf /etc/init.d/root         /etc/runlevels/default/root &&
    ln -sf /etc/init.d/sshd         /etc/runlevels/default/sshd &&
    ln -sf /etc/init.d/devfs        /etc/runlevels/boot/devfs &&
    ln -sf /etc/init.d/procfs       /etc/runlevels/boot/procfs &&
    ln -sf /etc/init.d/sysfs        /etc/runlevels/boot/sysfs &&
    ln -sf /etc/init.d/networking   /etc/runlevels/boot/networking &&
    mkdir -p /var/empty &&
    chmod 755 /var/empty &&
    ssh-keygen -A &&
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&
    grep -q 'PermitRootLogin yes' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config &&
    echo 'Port 22' >> /etc/ssh/sshd_config &&
    echo 'ListenAddress 0.0.0.0' >> /etc/ssh/sshd_config &&
    echo \"root:$ROOT_PASS\" | chpasswd &&
    adduser -D user &&
    echo \"user:$USER_PASS\" | chpasswd &&
    mkdir -p /home/user/bin &&
    chown -R user:user /home/user &&
    printf 'auto lo\niface lo inet loopback\nauto eth0\niface eth0 inet static\n    address 10.0.0.2\n    netmask 255.255.255.0\n    gateway 10.0.0.1\n' > /etc/network/interfaces &&
    printf 'nameserver 8.8.8.8\n' > /etc/resolv.conf &&
    for d in bin etc lib root sbin usr home var; do tar c \"/\$d\" | tar x -C /my-rootfs; done &&
    for dir in dev proc run sys tmp; do mkdir -p /my-rootfs/\${dir}; done
"


echo "[6b/13] Copie Binaire..."

# 3. Copie du programme compagnon pour le compte USER
# On suppose qu'il est compilé et prêt. S'il n'existe pas, on ignore sans planter.
if [ -f "$COMPANION_BIN" ]; then
    sudo mkdir -p "$ROOTFS/usr/local/bin"
    sudo cp "$COMPANION_BIN" "$ROOTFS/usr/local/bin/rk_demo"
    sudo chmod 755 "$ROOTFS/usr/local/bin/rk_demo"
    echo "    → Binaire compagnon installé pour user."
else
    echo "    → Attention: Binaire compagnon '$COMPANION_BIN' introuvable."
fi


echo "[7/12] Installation du noyau et GRUB..."
sudo mkdir -p "$ROOTFS/boot/grub"
sudo cp "$KERNEL" "$ROOTFS/boot/vmlinuz"

echo "[7b/12] Installation des modules noyau dans le rootfs..."
# On utilise make modules_install en disant de tout mettre dans ROOTFS
# Cela va créer /lib/modules/6.18.16/kernel/fs/... etc.
sudo make -C "$KERNEL_DIR/../../.." modules_install INSTALL_MOD_PATH="$ROOTFS"



echo "[7c/12] Création du dossier updates pour modules out-of-tree..."
KVER=$(ls "$ROOTFS/lib/modules/")
echo "    → Kernel version: $KVER"
sudo mkdir -p "$ROOTFS/lib/modules/$KVER/updates"
echo "    → Dossier updates créé: /lib/modules/$KVER/updates"


echo "[8/12] Copie du module"
sudo mkdir -p "$ROOTFS/root/rootkit"

if [ -z "$RK_KO_NAME" ] || [ ! -f "$PROJ_DIR/rootkit_module/$RK_KO_NAME.ko" ]; then
    echo "    → ERREUR: module .ko introuvable. Lance 'make modules' dans rootkit_module d'abord."
    exit 1
fi
sudo cp "$PROJ_DIR/rootkit_module/$RK_KO_NAME.ko" "$ROOTFS/root/rootkit/$RK_KO_NAME.ko"
echo "    → Module copié : $RK_KO_NAME.ko"

sudo tee "$ROOTFS/boot/grub/grub.cfg" > /dev/null <<'EOF'
serial
terminal_input serial
terminal_output serial
set root=(hd0,1)
menuentry "Linux2600" {
    linux /boot/vmlinuz root=/dev/sda1 console=ttyS0
}
EOF

echo "[9/12] Installation de GRUB..."
sudo grub-install --directory=/usr/lib/grub/i386-pc \
    --boot-directory="$ROOTFS/boot" "$LOOP"

echo "[10/12] Démontage et nettoyage..."
echo "[Nettoyage] Suppression caches apk..."
sudo rm -rf "$ROOTFS"/var/cache/apk/*
sudo rm -rf "$ROOTFS"/tmp/*

sudo umount "$ROOTFS"
sudo losetup -d "$LOOP"

echo "[11/12] Termine!"
echo ""
echo "Image prete : $DISK_IMG"
echo ""
echo "Lance la VM avec :"
echo " qemu-system-x86_64 -hda $DISK_IMG -m 2G -nographic -serial mon:stdio"
echo ""
echo "------------------------------------------------"
echo "IDENTIFIANTS :"
echo "  root : $ROOT_PASS"
echo "  user : $USER_PASS"
echo "---------------------------------------------"
echo "Commandes utiles dans la VM :"
echo "  mkdir /tmp   # créer le repertoire /tmp"
echo "  insmod /root/rootkit/$RK_KO_NAME.ko    # charger le module"
echo "  /usr/local/bin/rk_demo uid             # tester via companion"
echo "  reboot 						  # pour vérifier la persistance"
echo "[12/13] Conversion en QCOW2 compressé..."

qemu-img convert -O qcow2 -c "$DISK_IMG" disk.qcow2

echo "Image finale : disk.qcow2"

echo "[13/13] Configuration réseau host (TAP + NAT)..."
TAP="tap0"
HOST_IP="10.0.0.1"
SUBNET="10.0.0.0/24"
HOST_IFACE=$(ip route | awk '/default/{print $5; exit}')

sudo ip link del "$TAP" 2>/dev/null || true
sudo ip tuntap add "$TAP" mode tap user "$USER"
sudo ip addr add "$HOST_IP/24" dev "$TAP"
sudo ip link set "$TAP" up
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
sudo iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$HOST_IFACE" -j MASQUERADE
echo "[+] TAP $TAP ($HOST_IP) + NAT → $HOST_IFACE"
echo ""
echo "Lance la VM avec :"
echo "  qemu-system-x86_64 -drive file=disk.qcow2,format=qcow2 -m 2G -nographic -enable-kvm \\"
echo "    -netdev tap,id=net0,ifname=$TAP,script=no,downscript=no -device e1000,netdev=net0"
echo ""
echo "Dans la VM, le C2 est joignable sur : $HOST_IP:4444"
