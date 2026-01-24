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
import csv
import io
import ipaddress
import threading

# Optional color support
try:
    from colorama import init as _col_init
    from colorama import Fore, Style
    _col_init(autoreset=True)
    COLOR_AVAILABLE = True
except Exception:
    COLOR_AVAILABLE = False
    class Fore:
        GREEN = ''
        RED = ''
        YELLOW = ''
        CYAN = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''


class TokenBucket:
    """Simple token bucket for rate limiting (tokens per second).
    Call `consume()` before performing an action to ensure rate limit.
    """
    def __init__(self, rate, capacity=1):
        self.rate = float(rate)
        self.capacity = float(max(1, capacity))
        self._tokens = float(self.capacity)
        self._last = time.monotonic()

    def consume(self, tokens=1):
        tokens = float(tokens)
        while True:
            now = time.monotonic()
            elapsed = now - self._last
            # refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            # sleep a tiny bit to wait for tokens
            to_wait = (tokens - self._tokens) / max(self.rate, 1e-6)
            time.sleep(min(0.1, max(0.001, to_wait)))


# Nota: Com o modelo de batching no SYN scan, o Semaphore não é mais necessário.
# O sr() no Scapy usa uma única captura por lote, eliminando a pressão no Npcap.


def get_service_name(port):
    """Obtém o nome do serviço para uma porta TCP.
    Usa socket.getservbyport (banco de dados do SO - mais completo que listas).
    Retorna 'unknown' se não encontrado.
    """
    try:
        return socket.getservbyport(port, 'tcp')
    except (OSError, socket.error):
        return 'unknown'


def scan_port(host, port, timeout, family=socket.AF_INET):
    # Create socket for the appropriate address family
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
    except Exception:
        return port, 'error'
    s.settimeout(timeout)
    try:
        if family == socket.AF_INET6:
            addr = (host, port, 0, 0)
        else:
            addr = (host, port)
        s.connect(addr)
        s.close()
        return port, 'open'
    except ConnectionRefusedError:
        return port, 'closed'
    except socket.timeout:
        return port, 'filtered'
    except Exception:
        return port, 'error'


def scan_port_with_retries(host, port, timeout, family=socket.AF_INET, max_retries=0, backoff=0.5):
    """Wrapper around scan_port that retries on non-open results with exponential backoff.
    `max_retries` is the number of additional attempts (0 = no retry).
    """
    attempts = max(1, int(max_retries) + 1)
    for attempt in range(attempts):
        p, status = scan_port(host, port, timeout, family)
        if status == 'open' or attempt == attempts - 1:
            return p, status
        # Exponential backoff with slight jitter
        wait = backoff * (2 ** attempt) * (0.8 + random.random() * 0.4)
        time.sleep(min(wait, 5))
    return port, 'error'


def save_results_csv(filename, results, open_ports, services_map, args):
    """Save results to CSV format."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'State', 'Service'])
        for p in sorted(results.keys()):
            info = results[p]
            state = info['state'] if isinstance(info, dict) else info
            service = info['service'] if isinstance(info, dict) else services_map.get(p, 'unknown')
            writer.writerow([p, state, service])


def save_results_ndjson(filename, results, open_ports, services_map, args):
    """Save results to NDJSON format (one JSON per line)."""
    with open(filename, 'w', encoding='utf-8') as f:
        for p in sorted(results.keys()):
            info = results[p]
            state = info['state'] if isinstance(info, dict) else info
            service = info['service'] if isinstance(info, dict) else services_map.get(p, 'unknown')
            line = json.dumps({'port': p, 'state': state, 'service': service})
            f.write(line + '\n')


def save_results_xml(filename, results, open_ports, services_map, args):
    """Save results to XML format."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(f'<scan target="{args.target}" start="{args.start}" end="{args.end}">\n')
        for p in sorted(results.keys()):
            info = results[p]
            state = info['state'] if isinstance(info, dict) else info
            service = info['service'] if isinstance(info, dict) else services_map.get(p, 'unknown')
            f.write(f'  <port number="{p}" state="{state}" service="{service}" />\n')
        f.write('</scan>')


def save_results(filename, format_type, results, open_ports, services_map, args):
    """Wrapper to save results in the specified format."""
    if format_type == 'csv':
        save_results_csv(filename, results, open_ports, services_map, args)
    elif format_type == 'ndjson':
        save_results_ndjson(filename, results, open_ports, services_map, args)
    elif format_type == 'xml':
        save_results_xml(filename, results, open_ports, services_map, args)
    else:
        # Default to JSON
        simple_results = {p: (results[p]['state'] if isinstance(results[p], dict) else results[p]) for p in results}
        services_map_out = {p: (results[p]['service'] if isinstance(results[p], dict) else get_service_name(p)) for p in sorted(open_ports)}
        open_ports_detailed = [{'port': p, 'service': services_map_out.get(p, get_service_name(p))} for p in sorted(open_ports)]
        out = {
            'target': args.target,
            'target_ip': args.target_ip,
            'start': args.start,
            'end': args.end,
            'open_ports': open_ports_detailed,
            'results': simple_results,
            'services': services_map_out,
            'elapsed': args.elapsed,
            'mac': args.mac,
            'ip_version': args.ip_version,
            'method': getattr(args, 'method', 'connect')
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)


def is_private_ip(ip_str):
    """Verifica se um IP é privado (local). Retorna True/False.
    IPs privados: 10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x (loopback), 169.254.x.x (link-local)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return False


def get_mac_for_ip(ip, timeout=0.5):
    """Tenta obter o MAC address do `ip` consultando a tabela ARP local.
    Estratégia:
    1. Se IP é público (externo), retorna None (ARP não funciona fora da rede local)
    2. Tenta usar Scapy getmacbyip() se disponível (mais rápido e preciso)
    3. Fallback: ping + arp -a/arp -n (método tradicional com timeouts maiores)
    
    Retorna o MAC como string ou None se não encontrado.
    """
    # Verificação 1: Se é IP público, não insista
    if not is_private_ip(ip):
        print(Fore.YELLOW + f'⚠️  {ip} é um IP público (fora da rede local). ARP não descobrirá seu MAC.' + Style.RESET_ALL)
        return None
    
    # Verificação 2: Tenta Scapy getmacbyip (nativo, rápido e preciso)
    try:
        from scapy.arch import getmacbyip
        mac = getmacbyip(ip)
        if mac and mac != '00:00:00:00:00:00':
            return mac
    except Exception:
        pass
    
    # Fallback: Método tradicional (ping + ARP table lookup) com timeouts maiores
    system = platform.system().lower()
    ping_timeout = max(1.0, timeout * 2)  # Aumento timeout para 2x
    
    # Ping com múltiplas tentativas para popular ARP cache
    try:
        if system == 'windows':
            ping_cmd = ['ping', '-n', '2', '-w', str(int(ping_timeout * 1000)), ip]  # 2 pings em vez de 1
        else:
            ping_cmd = ['ping', '-c', '2', '-W', str(int(max(1, ping_timeout))), ip]
        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=ping_timeout + 1)
    except Exception:
        pass

    try:
        if system == 'windows':
            out = subprocess.check_output(['arp', '-a'], encoding='utf-8', errors='ignore')
            # Windows arp -a lines:  192.168.1.10           01-23-45-67-89-ab     dynamic
            # Melhor regex: evita multicast (01-00-5e) e broadcast (ff-ff)
            m = re.search(rf'^{re.escape(ip)}\s+([0-9a-fA-F][0-9a-fA-F](?:[\-:][0-9a-fA-F][0-9a-fA-F]){{5}})\s+', out, re.MULTILINE)
            if m:
                mac = m.group(1)
                # Rejeita multicast e broadcast
                if not mac.upper().startswith(('01-00-5E', 'FF-FF')):
                    return mac
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
    parser.add_argument('--rate-limit', type=float, default=0.0, help='Máximo de tentativas por segundo (0 = sem limite)')
    parser.add_argument('--max-retries', type=int, default=0, help='Número máximo de tentativas adicionais para portas não abertas (default 0)')
    parser.add_argument('--retry-backoff', type=float, default=0.5, help='Backoff base em segundos entre tentativas (exponencial)')
    parser.add_argument('--syn', action='store_true', help='Usar SYN scan com Scapy (requer Npcap/Admin)')
    parser.add_argument('--mac', action='store_true', help='Obter endereço MAC do alvo usando ARP (rede local)')
    parser.add_argument('--format', choices=['json', 'csv', 'ndjson', 'xml'], default='json', help='Formato de saída (padrão: json)')
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument('--pretty', dest='pretty', action='store_true', help='Mostrar saída formatada/colorida')
    grp.add_argument('--no-pretty', dest='pretty', action='store_false', help='Desabilitar saída formatada')
    parser.set_defaults(pretty=True)
    # Modo interativo quando nenhum argumento é passado
    if len(sys.argv) == 1:
        print('\n' + Fore.CYAN + Style.BRIGHT + '=' * 60)
        print('  SCANNER DE PORTAS - MODO INTERATIVO')
        print('=' * 60 + Style.RESET_ALL + '\n')
        
        target = input(Fore.YELLOW + '-> IP ou hostname: ' + Style.RESET_ALL).strip()
        if not target:
            print(Fore.RED + '[!] Alvo é obrigatório.' + Style.RESET_ALL)
            return
        
        print('\n' + Fore.YELLOW + '[*] Opções de scan:' + Style.RESET_ALL)
        print('  1) Scan rápido (portas 1-1024, ~5s típico)')
        print('  2) Scan completo (1-65535, ~30-60s típico)')
        print('  3) Scan customizado (escolha intervalo e workers)')
        choice = input(Fore.CYAN + 'Escolha (1/2/3, default=1): ' + Style.RESET_ALL).strip() or '1'
        
        if choice == '2':
            start, end = 1, 65535
            workers = 500
        elif choice == '3':
            start = input(Fore.CYAN + 'Porta inicial (default 1): ' + Style.RESET_ALL).strip() or '1'
            end = input(Fore.CYAN + 'Porta final (default 65535): ' + Style.RESET_ALL).strip() or '65535'
            workers = input(Fore.CYAN + 'Workers/threads (default 200): ' + Style.RESET_ALL).strip() or '200'
        else:
            start, end, workers = 1, 1024, 200
        
        print('\n' + Fore.YELLOW + '[*] Opções adicionais:' + Style.RESET_ALL)
        use_mac = input(Fore.CYAN + 'Obter MAC? (s/n, default=n): ' + Style.RESET_ALL).strip().lower() == 's'
        use_syn = input(Fore.CYAN + 'SYN scan (Batch Mode)? Requer admin/Npcap (s/n, default=n): ' + Style.RESET_ALL).strip().lower() == 's'
        if use_syn:
            print(Fore.GREEN + '[+] SYN Scan com Batching: Portas agrupadas em lotes de 500 para máxima velocidade.' + Style.RESET_ALL)
            print(Fore.CYAN + '    Estimativa: ~0.5-2s para 65535 portas em rede local.' + Style.RESET_ALL)
        
        print('\n' + Fore.YELLOW + '[*] Formato de saída:' + Style.RESET_ALL)
        print('  1) JSON (padrão)')
        print('  2) CSV')
        print('  3) NDJSON')
        print('  4) XML')
        fmt_choice = input(Fore.CYAN + 'Escolha (1/2/3/4, default=1): ' + Style.RESET_ALL).strip() or '1'
        fmt_map = {'1': 'json', '2': 'csv', '3': 'ndjson', '4': 'xml'}
        fmt = fmt_map.get(fmt_choice, 'json')
        
        ext_map = {'json': '.json', 'csv': '.csv', 'ndjson': '.ndjson', 'xml': '.xml'}
        save = f'open_ports{ext_map[fmt]}'
        
        # Print a visual summary of the scan configuration
        print('\n' + Fore.CYAN + Style.BRIGHT + '[RESUMO DA CONFIGURACAO]' + Style.RESET_ALL)
        print(f'  Alvo: {Fore.GREEN}{target}{Style.RESET_ALL}')
        print(f'  Portas: {Fore.GREEN}{start}-{end}{Style.RESET_ALL}')
        print(f'  Workers: {Fore.GREEN}{workers}{Style.RESET_ALL}')
        print(f'  MAC Lookup: {Fore.GREEN if use_mac else Fore.RED}{"Sim" if use_mac else "Não"}{Style.RESET_ALL}')
        print(f'  SYN Scan: {Fore.GREEN if use_syn else Fore.RED}{"Sim (Batch Mode)" if use_syn else "Não (Connect Scan)"}{Style.RESET_ALL}')
        print(f'  Formato: {Fore.GREEN}{fmt.upper()}{Style.RESET_ALL}')
        print(f'  Salvar em: {Fore.GREEN}{save}{Style.RESET_ALL}')
        print(Fore.CYAN + Style.BRIGHT + '-' * 60 + Style.RESET_ALL + '\n')
        
        timeout = 0.5
        rate = 0
        rate_limit = 0
        max_retries = 0
        retry_backoff = 0.5
        
        args = argparse.Namespace(
            target=target, start=int(start), end=int(end), timeout=float(timeout),
            workers=int(workers), save=save, rate=float(rate), syn=use_syn, mac=use_mac,
            rate_limit=float(rate_limit), max_retries=int(max_retries), retry_backoff=float(retry_backoff),
            format=fmt, pretty=True, target_ip='', elapsed=0, ip_version=4, method='connect'
        )
    else:
        args = parser.parse_args()

    # Resolve target to support IPv4 and IPv6
    try:
        addrinfos = socket.getaddrinfo(args.target, None)
        family = addrinfos[0][0]
        target_ip = addrinfos[0][4][0]
        args.target_ip = target_ip
        args.ip_version = 6 if family == socket.AF_INET6 else 4
    except Exception as e:
        print(Fore.RED + 'Falha ao resolver host:' + Style.RESET_ALL, e)
        return

    mac_addr = None
    if getattr(args, 'mac', False):
        if family == socket.AF_INET6:
            print('MAC via ARP não aplicável a IPv6; pulando lookup de MAC para IPv6.')
        else:
            mac_addr = get_mac_for_ip(target_ip, args.timeout)
            if mac_addr:
                print(f'MAC: {mac_addr}')
            else:
                print('MAC não encontrado (pode estar fora da rede local ou bloqueado).')

    # === NOVO BLOCO SYN SCAN (BATCHING MODE) ===
    # Resolve OSError [Errno 22] no Windows reduzindo o número de sniffers abertos
    if getattr(args, 'syn', False):
        try:
            from scapy.all import conf, IP, IPv6, TCP, sr, send, getmacbyip
        except Exception as e:
            print(Fore.RED + f'Scapy não disponível: {e}' + Style.RESET_ALL)
            return

        conf.verb = 0  # Silencia logs do Scapy
        print(Fore.CYAN + f'Iniciando SYN scan otimizado (Batch Mode) em {target_ip}...' + Style.RESET_ALL)

        # 1. Obter MAC estilo Nmap (ARP)
        if args.mac and family == socket.AF_INET:
            try:
                mac = getmacbyip(target_ip)
                if mac:
                    print(Fore.YELLOW + f'MAC Address: {mac.upper()}' + Style.RESET_ALL)
                    args.mac_address = mac
            except Exception:
                pass

        start_time = time.time()
        ports = list(range(max(1, args.start), min(65535, args.end) + 1))
        
        # Dividir em blocos de 500 portas para não sobrecarregar o buffer do Npcap/Windows
        # Isso reduz o número de sniffers de 8000 para ~16
        chunk_size = 500
        open_ports = []
        results = {}

        for i in range(0, len(ports), chunk_size):
            batch = ports[i:i + chunk_size]
            print(Fore.CYAN + f'  Escaneando lote {i//chunk_size + 1}: portas {batch[0]}-{batch[-1]}...' + Style.RESET_ALL)
            
            try:
                # sr() envia o lote inteiro e espera respostas de uma vez (estilo Nmap)
                # Usa APENAS 1 PIPE por lote, resolvendo OSError 22
                if family == socket.AF_INET6:
                    ans, unans = sr(IPv6(dst=target_ip)/TCP(dport=batch, flags="S"), 
                                   timeout=args.timeout, verbose=0, retry=0)
                else:
                    ans, unans = sr(IP(dst=target_ip)/TCP(dport=batch, flags="S"), 
                                   timeout=args.timeout, verbose=0, retry=0)

                for sent, received in ans:
                    sport = received.sport
                    if received.haslayer(TCP):
                        rflags = received[TCP].flags
                        if rflags == 0x12:  # SYN-ACK
                            service = get_service_name(sport)
                            if sport not in open_ports:
                                open_ports.append(sport)
                                results[sport] = {'state': 'open', 'service': service}
                                print(Fore.GREEN + f'  Open: {sport} ({service})' + Style.RESET_ALL)
                        elif rflags == 0x14:  # RST-ACK
                            service = get_service_name(sport)
                            results[sport] = {'state': 'closed', 'service': service}
                        else:
                            service = get_service_name(sport)
                            results[sport] = {'state': 'filtered', 'service': service}
                
                # Marcar portas que não responderam
                for sent in unans:
                    sport = sent[TCP].dport
                    if sport not in results:
                        results[sport] = {'state': 'filtered', 'service': get_service_name(sport)}

            except Exception as e:
                print(Fore.RED + f'  Erro no lote {i//chunk_size + 1}: {e}' + Style.RESET_ALL)
                # Continuar com próximo lote em caso de erro

        elapsed = time.time() - start_time
        print(Fore.CYAN + f'\nSYN scan completo em {elapsed:.2f}s' + Style.RESET_ALL)
        print('Portas abertas:', sorted(open_ports))

        if args.save:
            args.elapsed = elapsed
            save_results(args.save, args.format, results, sorted(open_ports), 
                        {p: results[p]['service'] for p in sorted(open_ports)}, args)
            print(Fore.GREEN + f'Resultados salvos em {args.save}' + Style.RESET_ALL)
        return

    ports = range(max(1, args.start), min(65535, args.end) + 1)
    open_ports = []
    results = {}

    print(f'Scanning {args.target} ({target_ip}) ports {args.start}-{args.end} with {args.workers} workers')
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_port = {}
        tb = TokenBucket(args.rate_limit, capacity=max(1, args.workers)) if args.rate_limit and args.rate_limit > 0 else None
        for p in ports:
            if tb:
                tb.consume()
            future = executor.submit(scan_port_with_retries, target_ip, p, args.timeout if args.timeout else 0.5, family, args.max_retries, args.retry_backoff)
            future_to_port[future] = p
            # Optional small pacing
            if args.rate > 0:
                time.sleep(args.rate)

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                    p, status = future.result()
                    service = get_service_name(p)
                    results[p] = {'state': status, 'service': service}
                    # Only mark as open if status is truly 'open'
                    if status == 'open':
                        if p not in open_ports:
                            open_ports.append(p)
                        print(Fore.GREEN + f'Open: {p} ({service})' + Style.RESET_ALL)
            except Exception as exc:
                    results[port] = {'state': 'error', 'service': None}

    elapsed = time.time() - start_time
    print('\nScan completo em {:.2f}s'.format(elapsed))
    print('Portas abertas:', sorted(open_ports))

    # Print table similar to nmap: aligned columns PORT  STATE  SERVICE
    rows = []
    for p in sorted(results.keys()):
        info = results[p]
        state = info['state'] if isinstance(info, dict) else info
        service = info['service'] if isinstance(info, dict) else get_service_name(p)
        rows.append((f"{p}/tcp", state, service))

    def print_pretty(rows, elapsed, target):
        total = len(rows)
        open_count = sum(1 for r in rows if r[1] == 'open')
        title = f" Scan results for {target} — {open_count}/{total} open (elapsed {elapsed:.2f}s) "
        sep = '=' * max(60, len(title) + 4)
        print(Fore.CYAN + Style.BRIGHT + sep)
        print(Fore.CYAN + Style.BRIGHT + title.center(len(sep)))
        print(Fore.CYAN + Style.BRIGHT + sep + Style.RESET_ALL)

        port_w = max([len(r[0]) for r in rows] + [4])
        state_w = max([len(r[1]) for r in rows] + [5])
        service_w = max([len(r[2]) for r in rows] + [7])

        header = f"| {'PORT'.ljust(port_w)} | {'STATE'.ljust(state_w)} | {'SERVICE'.ljust(service_w)} |"
        print(Fore.CYAN + header)
        print(Fore.CYAN + '-' * len(header) + Style.RESET_ALL)
        for port_str, state, service in rows:
            color = Fore.GREEN if state == 'open' else (Fore.YELLOW if state in ('filtered', 'no-response') else Fore.RED)
            state_txt = state.upper() if isinstance(state, str) else str(state)
            print(f"| {port_str.ljust(port_w)} | {color}{state_txt.ljust(state_w)}{Style.RESET_ALL} | {service.ljust(service_w)} |")

        print(Fore.CYAN + Style.BRIGHT + sep + Style.RESET_ALL)

    if getattr(args, 'pretty', False):
        print_pretty(rows, elapsed, args.target)
    else:
        port_w = max([len(r[0]) for r in rows] + [4])
        state_w = max([len(r[1]) for r in rows] + [5])
        service_w = max([len(r[2]) for r in rows] + [7])

        print()
        print(f"{ 'PORT'.ljust(port_w) }  { 'STATE'.ljust(state_w) }  { 'SERVICE'.ljust(service_w) }")
        for port_str, state, service in rows:
            print(f"{port_str.ljust(port_w)}  {state.ljust(state_w)}  {service.ljust(service_w)}")

    if args.save:
        services_map = {p: (results[p]['service'] if isinstance(results[p], dict) else get_service_name(p)) for p in sorted(open_ports)}
        args.elapsed = elapsed
        save_results(args.save, args.format, results, open_ports, services_map, args)
        print(Fore.GREEN + 'Resultados salvos em' + Style.RESET_ALL, args.save)


if __name__ == '__main__':
    main()
