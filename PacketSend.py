from scapy.all import conf, get_if_list, sendp, send, Ether, IP, IPv6, TCP, AsyncSniffer
import socket
import time
import json
import signal
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

# Force Scapy to use pcap/Npcap on Windows (requires Npcap installed)
conf.use_pcap = True

def enviar_syn(destino_ip, destino_porta, intervalo=0, count=0, duration=0, origem_ip=None, iface=None, logfile=None, capture=False, capture_iface=None):
    """Envia pacotes SYN.
    - intervalo: segundos entre pacotes (se 0, não espera)
    - count: número de pacotes a enviar (0 = indefinido)
    - duration: duração total em segundos (0 = indefinido)
    - logfile: caminho para salvar log JSON (se fornecido, salva lista de envios)
    """
    # Resolve the destination to determine address family (IPv4 vs IPv6)
    resolved_ip = destino_ip
    family = None
    try:
        infos = socket.getaddrinfo(destino_ip, None)
        if infos:
            family = infos[0][0]
            resolved_ip = infos[0][4][0]
    except Exception:
        # Fallback: try to detect IPv6 literal
        try:
            socket.inet_pton(socket.AF_INET6, destino_ip)
            family = socket.AF_INET6
        except Exception:
            family = socket.AF_INET

    is_ipv6 = (family == socket.AF_INET6)
    if is_ipv6:
        ip = IPv6(dst=resolved_ip)
        if origem_ip:
            try:
                ip.src = origem_ip
            except Exception:
                pass
    else:
        ip = IP(dst=resolved_ip)
        if origem_ip:
            try:
                ip.src = origem_ip
            except Exception:
                pass

    tcp = TCP(dport=destino_porta, flags='S', sport=12345)

    # Escolhe a interface: usa a passada, senão tenta a padrão do Scapy ou a primeira disponível
    if iface is None:
        try:
            iface = conf.iface or (get_if_list()[0] if get_if_list() else None)
        except Exception:
            iface = None

    sent = 0
    start_time = time.time()
    log = []
    captured = {'syns': 0}

    def _handle_capture(pkt):
        try:
            # Handle IPv4 and IPv6 packets
            if TCP in pkt:
                flags = pkt[TCP].flags
                if (flags & 0x02) and not (flags & 0x10):
                    # If destination matches (may be L2 or L3), increment
                    if (IPv6 in pkt and getattr(pkt[IPv6], 'dst', None) == destino_ip) or (IP in pkt and getattr(pkt[IP], 'dst', None) == destino_ip):
                        captured['syns'] += 1
        except Exception:
            pass

    sniffer = None
    if capture:
        # choose capture iface if not provided
        if capture_iface is None:
            capture_iface = iface
        try:
            # Use IPv6 BPF when appropriate
            if is_ipv6:
                bpf = f'ip6 and tcp and dst host {destino_ip}'
            else:
                bpf = f'tcp and dst host {destino_ip}'
            sniffer = AsyncSniffer(iface=capture_iface, filter=bpf, prn=_handle_capture)
            sniffer.start()
            print('Sniffer iniciado em', capture_iface)
        except Exception as e:
            print('Falha ao iniciar sniffer:', e)

    def save_log():
        if logfile:
            try:
                with open(logfile, 'w', encoding='utf-8') as f:
                    json.dump({'target': destino_ip, 'port': destino_porta, 'sent': sent, 'entries': log}, f, indent=2)
                print('Log salvo em', logfile)
            except Exception as e:
                print('Falha ao salvar log:', e)

    # handle Ctrl+C to save log
    def _signal_handler(sig, frame):
        print('\nInterrompido. Salvando log...')
        save_log()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _signal_handler)

    try:
        while True:
            # stop conditions
            if count > 0 and sent >= count:
                break
            if duration > 0 and (time.time() - start_time) >= duration:
                break

            # prepare packet and send
            if iface:
                pacote = Ether() / ip / tcp
                sendp(pacote, iface=iface, verbose=False)
            else:
                from scapy.all import send
                pacote = ip / tcp
                send(pacote, verbose=False)

            sent += 1
            ts = time.time()
            # Ensure iface is JSON-serializable (may be a NetworkInterface_Win object)
            if isinstance(iface, str) or iface is None:
                iface_name = iface
            else:
                iface_name = getattr(iface, 'name', str(iface))
            log_entry = {'ts': ts, 'src': origem_ip or 'default', 'dst': destino_ip, 'dport': destino_porta, 'iface': iface_name}
            log_entry['ip_version'] = 6 if is_ipv6 else 4
            log.append(log_entry)
            print(f"[{sent}] Pacote SYN enviado para {destino_ip}:{destino_porta} (iface={iface})")

            if intervalo > 0:
                time.sleep(intervalo)

    finally:
        # stop sniffer if running
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        # include captured count into log file
        if logfile:
            try:
                # append captured info
                with open(logfile, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                data = {'target': destino_ip, 'port': destino_porta, 'sent': sent, 'entries': log}
            data.setdefault('captured', {})
            data['captured']['syns'] = captured.get('syns', 0)
            data['ip_version'] = 6 if is_ipv6 else 4
            try:
                with open(logfile, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print('Falha ao atualizar log com captura:', e)
        save_log()


if __name__ == "__main__":
    print('\n' + Fore.CYAN + Style.BRIGHT + '=' * 60)
    print('  GERADOR DE PACOTES SYN - MODO INTERATIVO')
    print('=' * 60 + Style.RESET_ALL + '\n')
    
    ip_destino = input(Fore.YELLOW + '→ IP de destino: ' + Style.RESET_ALL).strip()
    if not ip_destino:
        print(Fore.RED + 'IP de destino obrigatório' + Style.RESET_ALL)
        raise SystemExit(1)
    
    try:
        porta_destino = int(input(Fore.YELLOW + '→ Porta de destino: ' + Style.RESET_ALL).strip() or 0)
    except ValueError:
        print(Fore.RED + 'Porta inválida' + Style.RESET_ALL)
        raise SystemExit(1)
    
    print('\n' + Fore.YELLOW + 'Escolha a taxa de envio:' + Style.RESET_ALL)
    print('1) Rápido (100 pps)')
    print('2) Moderado (10 pps)')
    print('3) Lento (1 pps)')
    print('4) Customizado')
    taxa_choice = input('Escolha (1/2/3/4, default=1): ').strip() or '1'
    
    if taxa_choice == '2':
        intervalo = 0.1
    elif taxa_choice == '3':
        intervalo = 1.0
    elif taxa_choice == '4':
        try:
            rate = float(input('Taxa (pacotes/s): ').strip() or 1)
            intervalo = 1.0 / rate if rate > 0 else 0
        except ValueError:
            intervalo = 0.5
    else:  # taxa_choice == '1'
        intervalo = 0.01
    
    print('\n' + Fore.YELLOW + 'Duração do envio:' + Style.RESET_ALL)
    print('1) 10 pacotes')
    print('2) 100 pacotes')
    print('3) 1000 pacotes')
    print('4) Contínuo (Ctrl+C para parar)')
    duracao_choice = input('Escolha (1/2/3/4, default=1): ').strip() or '1'
    
    if duracao_choice == '2':
        count = 100
    elif duracao_choice == '3':
        count = 1000
    elif duracao_choice == '4':
        count = 0
    else:  # duracao_choice == '1'
        count = 10
    
    duration = 0
    ip_origem = input(Fore.YELLOW + '→ IP de origem (Enter para automático): ' + Style.RESET_ALL).strip() or None
    iface = input(Fore.YELLOW + '→ Interface (Enter para padrão): ' + Style.RESET_ALL).strip() or None
    logfile = input(Fore.YELLOW + '→ Arquivo de log (Enter para open_send_log.json): ' + Style.RESET_ALL).strip() or 'open_send_log.json'
    
    print('\n' + Fore.CYAN + 'Iniciando envio de SYNs...' + Style.RESET_ALL + '\n')
    enviar_syn(ip_destino, porta_destino, intervalo=intervalo, count=count, duration=duration, origem_ip=ip_origem, iface=iface, logfile=logfile)