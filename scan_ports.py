#!/usr/bin/env python3
"""
scan_ports.py
Rápido scanner TCP (connect scan) concorrente em Python.
Uso seguro em Windows (não precisa de Npcap). Faça apenas em alvos autorizados.

Exemplos:
  python scan_ports.py 192.168.92.212 --start 1 --end 1024 --workers 200 --timeout 0.5
  python scan_ports.py example.com -s 1 -e 65535 -w 500 -t 0.3 --save results.json
"""
"""
# scan rápido portas 1-1024
python scan_ports.py 192.168.92.212 --start 1 --end 1024 --workers 200 --timeout 0.5
# scan completo (pode demorar). Salva resultado:
python scan_ports.py 192.168.92.212 --start 1 --end 65535 --workers 500 --timeout 0.3 --save open_ports.json
"""
import socket
import argparse
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import subprocess
import platform
import re


def scan_port(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return port, 'open'
    except ConnectionRefusedError:
        return port, 'closed'
    except socket.timeout:
        return port, 'filtered'
    except Exception:
        return port, 'error'


def get_mac_for_ip(ip, timeout=0.5):
    """Tenta obter o MAC address do `ip` consultando a tabela ARP local.
    Faz um ping rápido para popular a cache ARP e então executa comandos
    locais (`arp -a`, `ip neigh`, `arp -n`) conforme o SO.
    Retorna o MAC como string ou None se não encontrado.
    """
    system = platform.system().lower()
    # Ping to populate ARP cache
    try:
        if system == 'windows':
            ping_cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
        else:
            ping_cmd = ['ping', '-c', '1', '-W', str(int(max(1, timeout)) ), ip]
        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
    except Exception:
        pass

    try:
        if system == 'windows':
            out = subprocess.check_output(['arp', '-a'], encoding='utf-8', errors='ignore')
            # Windows arp -a lines:  192.168.1.10           01-23-45-67-89-ab     dynamic
            m = re.search(rf'^{re.escape(ip)}\s+([0-9a-fA-F\-:]+)\s+', out, re.MULTILINE)
            if m:
                return m.group(1)
        else:
            # Try `ip neigh` first
            try:
                out = subprocess.check_output(['ip', 'neigh'], encoding='utf-8', errors='ignore')
                m = re.search(rf'^{re.escape(ip)}\s+.*lladdr\s+([0-9a-fA-F:]+)', out, re.MULTILINE)
                if m:
                    return m.group(1)
            except Exception:
                pass
            # Fallback to arp -n
            try:
                out = subprocess.check_output(['arp', '-n', ip], encoding='utf-8', errors='ignore')
                m = re.search(r'(([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})', out)
                if m:
                    return m.group(1)
            except Exception:
                pass
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description='TCP connect port scanner (concurrent)')
    parser.add_argument('target', help='IP ou hostname a escanear')
    parser.add_argument('--start', '-s', type=int, default=1, help='Porta inicial (default: 1)')
    parser.add_argument('--end', '-e', type=int, default=1024, help='Porta final (inclusive) (default: 1024)')
    parser.add_argument('--timeout', '-t', type=float, default=0.5, help='Timeout por tentativa (segundos)')
    parser.add_argument('--workers', '-w', type=int, default=200, help='Número de threads concorrentes')
    parser.add_argument('--save', help='Salvar resultado em JSON')
    parser.add_argument('--rate', type=float, default=0.0, help='Delay (s) entre submissões de tarefas para reduzir carga (default 0)')
    parser.add_argument('--syn', action='store_true', help='Usar SYN scan com Scapy (requer Npcap/Admin)')
    parser.add_argument('--mac', action='store_true', help='Obter endereço MAC do alvo usando ARP (rede local)')
    # Modo interativo quando nenhum argumento é passado
    if len(sys.argv) == 1:
        print('Modo interativo: insira os valores solicitados (Enter = padrão)')
        target = input('Digite o IP ou hostname alvo: ').strip()
        if not target:
            print('Alvo é obrigatório.')
            return
        start = input('Porta inicial (default 1): ').strip() or '1'
        end = input('Porta final (default 1024): ').strip() or '1024'
        timeout = input('Timeout por tentativa (s) (default 0.5): ').strip() or '0.5'
        workers = input('Número de workers/threads (default 200): ').strip() or '200'
        rate = input('Delay entre submissões (s) (default 0): ').strip() or '0'
        save = 'open_ports.json'
        args = argparse.Namespace(target=target, start=int(start), end=int(end), timeout=float(timeout), workers=int(workers), save=save, rate=float(rate), syn=False)
    else:
        args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except Exception as e:
        print('Falha ao resolver host:', e)
        return

    mac_addr = None
    if getattr(args, 'mac', False):
        mac_addr = get_mac_for_ip(target_ip, args.timeout)
        if mac_addr:
            print(f'MAC: {mac_addr}')
        else:
            print('MAC não encontrado (pode estar fora da rede local ou bloqueado).')

    # If SYN scan requested, use Scapy-based scan
    if getattr(args, 'syn', False):
        try:
            from scapy.all import conf, sr1, IP, TCP, send
        except Exception as e:
            print('Scapy não disponível: instale scapy e Npcap (e rode como Administrador).', e)
            return

        conf.use_pcap = True
        print('Iniciando SYN scan (Scapy). Certifique-se de executar como Administrador e ter Npcap instalado.')

        ports = range(max(1, args.start), min(65535, args.end) + 1)
        open_ports = []
        results = {}

        def syn_scan_port(host, port, timeout):
            sport = random.randint(1025, 65535)
            pkt = IP(dst=host)/TCP(dport=port, flags='S', sport=sport)
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is None:
                return port, 'no-response'
            if resp.haslayer(TCP):
                rflags = resp[TCP].flags
                if rflags & 0x12:  # SYN-ACK
                    rst = IP(dst=host)/TCP(dport=port, flags='R', sport=sport)
                    send(rst, verbose=0)
                    return port, 'open'
                elif rflags & 0x14:  # RST-ACK
                    return port, 'closed'
            return port, 'other'

        print(f'Scanning (SYN) {args.target} ({target_ip}) ports {args.start}-{args.end} with {args.workers} workers')
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_port = {executor.submit(syn_scan_port, target_ip, p, args.timeout): p for p in ports}
            # Optional small pacing
            if args.rate > 0:
                time.sleep(args.rate)

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    p, status = future.result()
                    results[p] = status
                    if status == 'open':
                        open_ports.append(p)
                        print(f'Open: {p}')
                except Exception:
                    results[port] = 'error'

        elapsed = time.time() - start_time
        print('\nSYN scan completo em {:.2f}s'.format(elapsed))
        print('Portas abertas:', sorted(open_ports))

        if args.save:
            out = {
                'target': args.target,
                'target_ip': target_ip,
                'start': args.start,
                'end': args.end,
                'open_ports': sorted(open_ports),
                'results': results,
                'elapsed': elapsed,
                'method': 'syn',
                'mac': mac_addr
            }
            with open(args.save, 'w', encoding='utf-8') as f:
                json.dump(out, f, indent=2)
            print('Resultados salvos em', args.save)
        return

    ports = range(max(1, args.start), min(65535, args.end) + 1)
    open_ports = []
    results = {}

    print(f'Scanning {args.target} ({target_ip}) ports {args.start}-{args.end} with {args.workers} workers')
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_port = {executor.submit(scan_port, target_ip, p, args.timeout): p for p in ports}
        # Optional small pacing
        if args.rate > 0:
            time.sleep(args.rate)

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                p, status = future.result()
                results[p] = status
                if status == 'open':
                    open_ports.append(p)
                    print(f'Open: {p}')
            except Exception as exc:
                results[port] = 'error'

    elapsed = time.time() - start_time
    print('\nScan completo em {:.2f}s'.format(elapsed))
    print('Portas abertas:', sorted(open_ports))

    if args.save:
        out = {
            'target': args.target,
            'target_ip': target_ip,
            'start': args.start,
            'end': args.end,
            'open_ports': sorted(open_ports),
            'results': results,
            'elapsed': elapsed,
            'mac': mac_addr
        }
        with open(args.save, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        print('Resultados salvos em', args.save)


if __name__ == '__main__':
    main()
