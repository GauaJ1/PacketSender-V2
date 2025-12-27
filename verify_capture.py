#!/usr/bin/env python3
from scapy.all import conf, get_if_list, sniff, TCP, IP, IPv6
import argparse
import sys
import subprocess
import platform
import re
import socket

conf.use_pcap = True

parser = argparse.ArgumentParser(description='Captura e conta SYNs para um destino na interface especificada')
parser.add_argument('--iface', '-i', help='Interface (ex: \\Device\\NPF_{...})', default=None)
parser.add_argument('--dest', '-d', help='IP de destino a observar')
parser.add_argument('--timeout', '-t', help='Segundos para capturar (default 5)', type=int, default=5)
parser.add_argument('--count', '-c', help='Número máximo de pacotes a capturar (0 = usar timeout)', type=int, default=0)
parser.add_argument('--mac', action='store_true', help='Tentar obter endereço MAC/LLA do destino (ARP para IPv4, NDP para IPv6)')
parser.add_argument('--ping-only', action='store_true', help='Executar apenas pings para verificar alcançabilidade (não precisa de iface)')
parser.add_argument('--ping-count', type=int, default=4, help='Número de pings a enviar em --ping-only (default 4)')

# Modo interativo se nenhum argumento foi passado
if len(sys.argv) == 1:
    if_list = get_if_list()
    print('Interfaces disponíveis:')
    for i, it in enumerate(if_list):
        print(f'  {i+1}. {it}')
    iface = input('Escolha iface (cole o nome ou pressione Enter para padrão): ').strip() or None
    dest = input('IP de destino a observar (obrigatório): ').strip()
    if not dest:
        print('IP de destino é obrigatório.')
        raise SystemExit(1)
    timeout = input('Timeout (segundos, default 5): ').strip() or '5'
    count = input('Número máximo de pacotes (0 = usar timeout, default 0): ').strip() or '0'
    do_mac = input('Tentar obter MAC/NDP? (y/N): ').strip().lower() == 'y'
    ping_only = input('Fazer apenas ping para verificar alcance? (y/N): ').strip().lower() == 'y'
    ping_count = input('Ping count (default 4): ').strip() or '4'
    args = argparse.Namespace(iface=iface, dest=dest, timeout=int(timeout), count=int(count), mac=do_mac, ping_only=ping_only, ping_count=int(ping_count))
else:
    args = parser.parse_args()

# Resolve destination and detect IPv4/IPv6
family = socket.AF_INET
try:
    infos = socket.getaddrinfo(args.dest, None)
    if infos:
        family = infos[0][0]
        resolved_dest = infos[0][4][0]
except Exception:
    try:
        socket.inet_pton(socket.AF_INET6, args.dest)
        family = socket.AF_INET6
        resolved_dest = args.dest
    except Exception:
        family = socket.AF_INET
        resolved_dest = args.dest

# If ping-only requested, perform ping(s) and exit
def ping_target(dest, count=4):
    system = platform.system().lower()
    cmd = []
    if system == 'windows':
        # Windows ping uses -n for count. For IPv6, add -6 flag.
        cmd = ['ping', '-n', str(count), dest]
        if family == socket.AF_INET6:
            cmd.insert(1, '-6')
    else:
        # Unix ping: use ping for IPv4, ping -6 for IPv6 (some systems use ping6)
        if family == socket.AF_INET6:
            # try iputils ping -6
            cmd = ['ping', '-6', '-c', str(count), args.dest]
        else:
            cmd = ['ping', '-c', str(count), args.dest]
    try:
        print('Executando:', ' '.join(cmd))
        subprocess.run(cmd, check=False)
    except Exception as e:
        print('Falha ao executar ping:', e)

if args.ping_only:
    ping_target(resolved_dest, args.ping_count)
    raise SystemExit(0)

if_list = get_if_list()
iface = args.iface or conf.iface or (if_list[0] if if_list else None)
if iface is None:
    print('Nenhuma interface disponível para captura. Verifique Npcap e privilégios.')
    raise SystemExit(1)

print(f'Capturando em iface: {iface} para destino: {resolved_dest} (timeout={args.timeout}s, count={args.count})')

syn_count = 0

def get_link_layer_addr(ip, timeout=0.5):
    system = platform.system().lower()
    # Try IPv4 ARP
    if family == socket.AF_INET:
        try:
            if system == 'windows':
                subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
                out = subprocess.check_output(['arp', '-a'], encoding='utf-8', errors='ignore')
                m = re.search(rf'^{re.escape(ip)}\s+([0-9a-fA-F\-:]+)\s+', out, re.MULTILINE)
                if m:
                    return m.group(1)
            else:
                subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
                try:
                    out = subprocess.check_output(['ip', 'neigh'], encoding='utf-8', errors='ignore')
                    m = re.search(rf'^{re.escape(ip)}\s+.*lladdr\s+([0-9a-fA-F:]+)', out, re.MULTILINE)
                    if m:
                        return m.group(1)
                except Exception:
                    out = subprocess.check_output(['arp', '-n', ip], encoding='utf-8', errors='ignore')
                    m = re.search(r'(([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})', out)
                    if m:
                        return m.group(1)
        except Exception:
            return None
    else:
        # IPv6: try NDP/neighbors
        try:
            if system == 'windows':
                subprocess.run(['ping', '-n', '1', '-6', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
                out = subprocess.check_output(['netsh', 'interface', 'ipv6', 'show', 'neighbors'], encoding='utf-8', errors='ignore')
                m = re.search(rf'{re.escape(ip)}\s+([0-9a-fA-F\-:]+)', out)
                if m:
                    return m.group(1)
            else:
                subprocess.run(['ping', '-6', '-c', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1)
                out = subprocess.check_output(['ip', '-6', 'neigh'], encoding='utf-8', errors='ignore')
                m = re.search(rf'^{re.escape(ip)}\s+.*lladdr\s+([0-9a-fA-F:]+)', out, re.MULTILINE)
                if m:
                    return m.group(1)
        except Exception:
            return None
    return None

def handle(pkt):
    global syn_count
    try:
        if TCP in pkt:
            flags = pkt[TCP].flags
            if (flags & 0x02) and not (flags & 0x10):
                # IPv4
                if IP in pkt and getattr(pkt[IP], 'dst', None) == resolved_dest:
                    syn_count += 1
                    print(f'[SYN] {pkt[IP].src} -> {pkt[IP].dst} : sport={pkt[TCP].sport} dport={pkt[TCP].dport}')
                # IPv6
                elif IPv6 in pkt and getattr(pkt[IPv6], 'dst', None) == resolved_dest:
                    syn_count += 1
                    print(f'[SYN] {pkt[IPv6].src} -> {pkt[IPv6].dst} : sport={pkt[TCP].sport} dport={pkt[TCP].dport}')
    except Exception:
        pass

# Use BPF filter to reduce carga; sniff will still call handle to confirmar flags
if family == socket.AF_INET6:
    bpf = f'ip6 and tcp and dst host {resolved_dest}'
else:
    bpf = f'tcp and dst host {resolved_dest}'

sniff_kwargs = dict(iface=iface, filter=bpf, prn=handle)
if args.count > 0:
    sniff_kwargs['count'] = args.count
else:
    sniff_kwargs['timeout'] = args.timeout

sniff(**sniff_kwargs)
print('Captura finalizada. SYNs capturados:', syn_count)

if args.mac:
    mac = get_link_layer_addr(resolved_dest)
    if mac:
        print('Endereço link-layer (MAC/NDP):', mac)
    else:
        print('MAC/NDP não encontrado (pode estar fora da rede local ou cache vazia).')
