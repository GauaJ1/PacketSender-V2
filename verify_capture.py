#!/usr/bin/env python3
from scapy.all import conf, get_if_list, sniff, TCP, IP
import argparse
import sys

conf.use_pcap = True

parser = argparse.ArgumentParser(description='Captura e conta SYNs para um destino na interface especificada')
parser.add_argument('--iface', '-i', help='Interface (ex: \\Device\\NPF_{...})', default=None)
parser.add_argument('--dest', '-d', help='IP de destino a observar')
parser.add_argument('--timeout', '-t', help='Segundos para capturar (default 5)', type=int, default=5)
parser.add_argument('--count', '-c', help='Número máximo de pacotes a capturar (0 = usar timeout)', type=int, default=0)

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
    args = argparse.Namespace(iface=iface, dest=dest, timeout=int(timeout), count=int(count))
else:
    args = parser.parse_args()

if_list = get_if_list()
iface = args.iface or conf.iface or (if_list[0] if if_list else None)
if iface is None:
    print('Nenhuma interface disponível para captura. Verifique Npcap e privilégios.')
    raise SystemExit(1)

print(f'Capturando em iface: {iface} para destino: {args.dest} (timeout={args.timeout}s, count={args.count})')

syn_count = 0

def handle(pkt):
    global syn_count
    if IP in pkt and TCP in pkt:
        # flags: SYN=0x02, ACK=0x10. Queremos SYN sem ACK (início de handshake)
        flags = pkt[TCP].flags
        if pkt[IP].dst == args.dest and (flags & 0x02) and not (flags & 0x10):
            syn_count += 1
            print(f'[SYN] {pkt[IP].src} -> {pkt[IP].dst} : sport={pkt[TCP].sport} dport={pkt[TCP].dport}')

# Use BPF filter to reduce carga; sniff will still call handle to confirmar flags
bpf = f'tcp and dst host {args.dest}'

sniff_kwargs = dict(iface=iface, filter=bpf, prn=handle)
if args.count > 0:
    sniff_kwargs['count'] = args.count
else:
    sniff_kwargs['timeout'] = args.timeout

sniff(**sniff_kwargs)
print('Captura finalizada. SYNs capturados:', syn_count)
