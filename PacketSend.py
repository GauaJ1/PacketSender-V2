#!/usr/bin/env python3
"""
PacketSend.py
Gerador de pacotes SYN (TCP) com suporte a IPv4/IPv6.
Modo interativo (padrão) ou CLI com --dst/--port.

Uso interativo:
    python PacketSend.py

Uso CLI:
    python PacketSend.py --dst 192.168.0.1 --port 80 --count 10
    python PacketSend.py --dst 192.168.0.1 --port 443 --count 0 --interval 0.1  # contínuo
    python PacketSend.py --help
"""
import sys
import socket
import time
import json
import signal
import argparse
import platform

from scapy.all import conf, get_if_list, sendp, send, Ether, IP, IPv6, TCP, AsyncSniffer

# Mover conf.use_pcap para apenas sistemas que precisam (Windows)
if platform.system().lower() == 'windows':
    try:
        conf.use_pcap = True
    except Exception:
        pass

# Suporte a cores (opcional)
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
        MAGENTA = ''
    class Style:
        BRIGHT = ''
        RESET_ALL = ''


def enviar_syn(destino_ip, destino_porta, intervalo=0, count=0, duration=0,
               origem_ip=None, iface=None, logfile=None, capture=False, capture_iface=None):
    """Envia pacotes SYN TCP.

    Args:
        destino_ip:     IP ou hostname de destino.
        destino_porta:  Porta TCP de destino.
        intervalo:      Segundos entre pacotes (0 = sem pausa).
        count:          Número de pacotes a enviar (0 = contínuo até Ctrl+C).
        duration:       Duração total em segundos (0 = sem limite de tempo).
        origem_ip:      IP de origem (None = automático).
        iface:          Interface de rede (None = padrão do Scapy).
        logfile:        Caminho para salvar log JSON.
        capture:        Se True, ativa sniffer para contar SYNs enviados/capturados.
        capture_iface:  Interface para captura (None = usa mesma de envio).
    """
    # Resolve destino: suporta IPv4, IPv6 e hostnames
    resolved_ip = destino_ip
    family = None
    try:
        infos = socket.getaddrinfo(destino_ip, None)
        if infos:
            family = infos[0][0]
            resolved_ip = infos[0][4][0]
    except Exception:
        try:
            socket.inet_pton(socket.AF_INET6, destino_ip)
            family = socket.AF_INET6
        except Exception:
            family = socket.AF_INET

    is_ipv6 = (family == socket.AF_INET6)
    if is_ipv6:
        ip_layer = IPv6(dst=resolved_ip)
        if origem_ip:
            try:
                ip_layer.src = origem_ip
            except Exception:
                pass
    else:
        ip_layer = IP(dst=resolved_ip)
        if origem_ip:
            try:
                ip_layer.src = origem_ip
            except Exception:
                pass

    tcp = TCP(dport=destino_porta, flags='S', sport=12345)

    # Interface de envio
    if iface is None:
        try:
            iface = conf.iface or (get_if_list()[0] if get_if_list() else None)
        except Exception:
            iface = None

    sent = 0
    start_time = time.time()
    log_entries = []
    captured = {'syns': 0}

    # --- Sniffer (opcional) ---
    def _handle_capture(pkt):
        try:
            if TCP in pkt:
                flags = pkt[TCP].flags
                if (flags & 0x02) and not (flags & 0x10):
                    dst_match = (
                        (IPv6 in pkt and getattr(pkt[IPv6], 'dst', None) == resolved_ip) or
                        (IP in pkt and getattr(pkt[IP], 'dst', None) == resolved_ip)
                    )
                    if dst_match:
                        captured['syns'] += 1
        except Exception:
            pass

    sniffer = None
    if capture:
        cap_iface = capture_iface or iface
        try:
            bpf = (f'ip6 and tcp and dst host {resolved_ip}' if is_ipv6
                   else f'tcp and dst host {resolved_ip}')
            sniffer = AsyncSniffer(iface=cap_iface, filter=bpf, prn=_handle_capture)
            sniffer.start()
            print(Fore.CYAN + f'[*] Sniffer iniciado em {cap_iface}' + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f'[!] Falha ao iniciar sniffer: {e}' + Style.RESET_ALL)

    # --- Salvar log (única função, chamada no finally) ---
    def _save_log_once():
        if not logfile:
            return
        data = {
            'target': destino_ip,
            'resolved_ip': resolved_ip,
            'port': destino_porta,
            'ip_version': 6 if is_ipv6 else 4,
            'sent': sent,
            'entries': log_entries,
        }
        if capture:
            data['captured'] = {'syns': captured.get('syns', 0)}
        try:
            with open(logfile, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(Fore.GREEN + f'[+] Log salvo em {logfile}' + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f'[!] Falha ao salvar log: {e}' + Style.RESET_ALL)

    # --- Ctrl+C handler ---
    def _signal_handler(sig, frame):
        print(Fore.YELLOW + '\n[!] Interrompido pelo usuário.' + Style.RESET_ALL)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _signal_handler)

    # --- Loop de envio ---
    try:
        while True:
            if count > 0 and sent >= count:
                break
            if duration > 0 and (time.time() - start_time) >= duration:
                break

            if iface:
                pacote = Ether() / ip_layer / tcp
                sendp(pacote, iface=iface, verbose=False)
            else:
                pacote = ip_layer / tcp
                send(pacote, verbose=False)

            sent += 1
            ts = time.time()
            iface_name = iface if isinstance(iface, str) else getattr(iface, 'name', str(iface))
            log_entries.append({
                'ts': ts,
                'src': origem_ip or 'default',
                'dst': destino_ip,
                'dport': destino_porta,
                'iface': iface_name,
                'ip_version': 6 if is_ipv6 else 4,
            })
            print(Fore.GREEN + f'[{sent}] SYN → {destino_ip}:{destino_porta}  (iface={iface_name})' + Style.RESET_ALL)

            if intervalo > 0:
                time.sleep(intervalo)

    except KeyboardInterrupt:
        pass
    finally:
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        _save_log_once()

    print(Fore.CYAN + f'\n[*] Total enviado: {sent} pacotes' + Style.RESET_ALL)
    if capture:
        print(Fore.CYAN + f'[*] SYNs capturados pelo sniffer: {captured["syns"]}' + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# CLI (argparse) — foco secundário; modo interativo é o principal
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        description='PacketSend — Gerador de pacotes SYN TCP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Exemplos:\n'
            '  python PacketSend.py --dst 192.168.0.1 --port 80 --count 10\n'
            '  python PacketSend.py --dst 192.168.0.1 --port 443 --count 0 --interval 0.5\n'
            '  python PacketSend.py  # modo interativo\n'
        )
    )
    p.add_argument('--dst', metavar='IP', help='IP ou hostname de destino')
    p.add_argument('--port', type=int, metavar='N', help='Porta TCP de destino')
    p.add_argument('--count', type=int, default=10,
                   help='Número de pacotes (0 = contínuo até Ctrl+C, default: 10)')
    p.add_argument('--interval', type=float, default=0.01,
                   help='Intervalo entre pacotes em segundos (default: 0.01 = 100 pps)')
    p.add_argument('--duration', type=float, default=0,
                   help='Duração máxima em segundos (0 = sem limite, default: 0)')
    p.add_argument('--src', metavar='IP', help='IP de origem (opcional, default: automático)')
    p.add_argument('--iface', metavar='IFACE', help='Interface de rede (opcional)')
    p.add_argument('--logfile', default='open_send_log.json',
                   help='Arquivo de log JSON (default: open_send_log.json)')
    p.add_argument('--capture', action='store_true',
                   help='Ativar sniffer para verificar pacotes enviados')
    return p


def _modo_interativo():
    print('\n' + Fore.CYAN + Style.BRIGHT + '=' * 60)
    print('  GERADOR DE PACOTES SYN - MODO INTERATIVO')
    print('=' * 60 + Style.RESET_ALL + '\n')

    ip_destino = input(Fore.YELLOW + '→ IP ou hostname de destino: ' + Style.RESET_ALL).strip()
    if not ip_destino:
        print(Fore.RED + '[!] IP de destino obrigatório.' + Style.RESET_ALL)
        raise SystemExit(1)

    try:
        porta_destino = int(input(Fore.YELLOW + '→ Porta de destino: ' + Style.RESET_ALL).strip() or 0)
    except ValueError:
        print(Fore.RED + '[!] Porta inválida.' + Style.RESET_ALL)
        raise SystemExit(1)

    # Taxa de envio
    print('\n' + Fore.YELLOW + '[*] Taxa de envio:' + Style.RESET_ALL)
    print('  1) Rápido    — 100 pps  (padrão)')
    print('  2) Moderado  — 10 pps')
    print('  3) Lento     — 1 pps')
    print('  4) Customizado')
    taxa_choice = input(Fore.CYAN + 'Escolha (1/2/3/4, default=1): ' + Style.RESET_ALL).strip() or '1'

    if taxa_choice == '2':
        intervalo = 0.1
    elif taxa_choice == '3':
        intervalo = 1.0
    elif taxa_choice == '4':
        try:
            rate = float(input(Fore.CYAN + '  Taxa (pacotes/s): ' + Style.RESET_ALL).strip() or 1)
            intervalo = 1.0 / rate if rate > 0 else 0
        except ValueError:
            intervalo = 0.5
    else:
        intervalo = 0.01

    # Quantidade
    print('\n' + Fore.YELLOW + '[*] Quantidade de pacotes:' + Style.RESET_ALL)
    print('  1) 10 pacotes    (padrão)')
    print('  2) 100 pacotes')
    print('  3) 1000 pacotes')
    print('  4) Contínuo (Ctrl+C para parar)')
    duracao_choice = input(Fore.CYAN + 'Escolha (1/2/3/4, default=1): ' + Style.RESET_ALL).strip() or '1'

    count_map = {'1': 10, '2': 100, '3': 1000, '4': 0}
    count = count_map.get(duracao_choice, 10)

    # Opções avançadas
    print('\n' + Fore.YELLOW + '[*] Opções avançadas:' + Style.RESET_ALL)
    ip_origem = input(Fore.CYAN + '→ IP de origem (Enter = automático): ' + Style.RESET_ALL).strip() or None
    iface = input(Fore.CYAN + '→ Interface (Enter = padrão): ' + Style.RESET_ALL).strip() or None
    logfile = input(Fore.CYAN + '→ Arquivo de log (Enter = open_send_log.json): ' + Style.RESET_ALL).strip() or 'open_send_log.json'
    use_capture = input(Fore.CYAN + '→ Ativar sniffer de captura? (s/n, default=n): ' + Style.RESET_ALL).strip().lower() == 's'

    # Resumo
    count_str = str(count) if count > 0 else '∞ (contínuo)'
    pps = f'{1/intervalo:.0f} pps' if intervalo > 0 else 'máximo'
    print('\n' + Fore.CYAN + Style.BRIGHT + '[RESUMO DA CONFIGURAÇÃO]' + Style.RESET_ALL)
    print(f'  Destino:   {Fore.GREEN}{ip_destino}:{porta_destino}{Style.RESET_ALL}')
    print(f'  Taxa:      {Fore.GREEN}{pps}{Style.RESET_ALL}')
    print(f'  Pacotes:   {Fore.GREEN}{count_str}{Style.RESET_ALL}')
    print(f'  Origem:    {Fore.GREEN}{ip_origem or "automático"}{Style.RESET_ALL}')
    print(f'  Interface: {Fore.GREEN}{iface or "padrão"}{Style.RESET_ALL}')
    print(f'  Log:       {Fore.GREEN}{logfile}{Style.RESET_ALL}')
    print(f'  Sniffer:   {Fore.GREEN if use_capture else Fore.RED}{"Ativo" if use_capture else "Desativado"}{Style.RESET_ALL}')
    print(Fore.CYAN + Style.BRIGHT + '-' * 60 + Style.RESET_ALL + '\n')

    print(Fore.CYAN + '[*] Iniciando envio de SYNs... (Ctrl+C para parar)' + Style.RESET_ALL + '\n')
    enviar_syn(
        ip_destino, porta_destino,
        intervalo=intervalo, count=count, duration=0,
        origem_ip=ip_origem, iface=iface, logfile=logfile,
        capture=use_capture,
    )


if __name__ == '__main__':
    # Se não foram passados argumentos CLI reconhecidos (--dst/--port), entra em modo interativo
    parser = _build_parser()
    args, unknown = parser.parse_known_args()

    if args.dst and args.port:
        # Modo CLI
        print(Fore.CYAN + f'[*] Enviando {args.count or "∞"} pacotes SYN para {args.dst}:{args.port}...' + Style.RESET_ALL)
        enviar_syn(
            args.dst, args.port,
            intervalo=args.interval,
            count=args.count,
            duration=args.duration,
            origem_ip=args.src,
            iface=args.iface,
            logfile=args.logfile,
            capture=args.capture,
        )
    else:
        # Modo interativo (foco principal)
        _modo_interativo()