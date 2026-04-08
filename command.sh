#!/bin/bash
set -e

# ─── CONFIG ───────────────────────────────────────────────────────────────────
DISK_IMG="../disk.img"
ROOTFS="/tmp/my-rootfs"
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="$PROJ_DIR/build-sys-linux-6.19.9/arch/x86/boot"   # adapte ce chemin si besoin
KERNEL="$KERNEL_DIR/bzImage"   # adapte ce chemin si besoin
COMPANION_BIN="$PROJ_DIR/rootkit_module/rootkit_malware" 
# ──────────────────────────────────────────────────────────────────────────────


ROOT_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
# -----------------------------------------------------------------------------

echo "[0/13] Configuration générée :"
echo "    → Root Password : $ROOT_PASS"
echo "    → User Password : $USER_PASS"


echo "[1/12] Nettoyage..."
sudo umount "$ROOTFS" 2>/dev/null || true
for loop in $(losetup -l | grep "$DISK_IMG" | awk '{print $1}'); do
    sudo losetup -d "$loop" 2>/dev/null || true
done
rm -f "$DISK_IMG"
rm -f disk.qcow2
mkdir -p "$ROOTFS"

echo "[2/12] Création de l'image disque..."
truncate -s 2000M "$DISK_IMG"
/sbin/parted -s "$DISK_IMG" mktable msdos
/sbin/parted -s "$DISK_IMG" mkpart primary ext4 1MiB "100%"
/sbin/parted -s "$DISK_IMG" set 1 boot on

echo "[3/12] Attachement loop..."
sudo losetup -Pf "$DISK_IMG"
LOOP=$(losetup -l | grep "$DISK_IMG" | awk '{print $1}')
echo "    → Loop device : $LOOP"

echo "[4/12] Formatage de la partition..."
sudo mkfs.ext4 "${LOOP}p1"

echo "[5/12] Montage..."
sudo mount "${LOOP}p1" "$ROOTFS"

echo "[6/12] Peuplement via Docker (Alpine)..."
sudo docker run --rm -v "$ROOTFS":/my-rootfs alpine sh -c "
    apk add openrc util-linux build-base musl-dev clang llvm bpftool libbpf-dev linux-headers tmux &&
    ln -s agetty /etc/init.d/agetty.ttyS0 &&
    echo ttyS0 > /etc/securetty &&
    rc-update add agetty.ttyS0 default &&
    rc-update add root default &&
    echo "root:$ROOT_PASS" | chpasswd &&
    adduser -D user &&
    echo "user:$USER_PASS" | chpasswd &&
    mkdir -p /home/user/bin &&
    chown -R user:user /home/user &&
    rc-update add devfs boot &&
    uname -r &&
    find / -name "*.ko" && 
    rc-update add procfs boot &&
    rc-update add sysfs boot && 
    for d in bin etc lib root sbin usr; do tar c \"/\$d\" | tar x -C /my-rootfs; done &&
    for dir in dev proc run sys var; do mkdir -p /my-rootfs/\${dir}; done
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

sudo cp -R "$PROJ_DIR/rootkit_module/rootkit.ko" "$ROOTFS/root/rootkit/"

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
echo "  Utilisateur ROOT : pass = $ROOT_PASS"
echo "  Utilisateur USER : pass = $USER_PASS"
echo "---------------------------------------------"
echo "Commandes utiles dans la VM :"
echo "  mkdir /tmp   # créer le repertoire /tmp"
echo "  cp exam/rootkit/rootkit.ko /tmp/rk_test.ko        # y mettre le module avec le nom attendu"
echo "  insmod /tmp/rk_test.ko          		  # charger le module"
echo "  reboot 						  # pour vérifier la persistance"
echo "[12/12] Conversion en QCOW2 compressé..."

qemu-img convert -O qcow2 -c "$DISK_IMG" disk.qcow2

echo "Image finale : disk.qcow2"
