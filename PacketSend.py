from scapy.all import conf, get_if_list, sendp, Ether, IP, TCP, AsyncSniffer
import time
import json
import signal
import threading

# Force Scapy to use pcap/Npcap on Windows (requires Npcap installed)
conf.use_pcap = True

def enviar_syn(destino_ip, destino_porta, intervalo=0, count=0, duration=0, origem_ip=None, iface=None, logfile=None, capture=False, capture_iface=None):
    """Envia pacotes SYN.
    - intervalo: segundos entre pacotes (se 0, não espera)
    - count: número de pacotes a enviar (0 = indefinido)
    - duration: duração total em segundos (0 = indefinido)
    - logfile: caminho para salvar log JSON (se fornecido, salva lista de envios)
    """
    ip = IP(dst=destino_ip)
    if origem_ip:
        ip.src = origem_ip

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
            if IP in pkt and TCP in pkt:
                # SYN without ACK
                flags = pkt[TCP].flags
                if (flags & 0x02) and not (flags & 0x10):
                    # If destination matches (may be L2 or L3), increment
                    if pkt[IP].dst == destino_ip:
                        captured['syns'] += 1
        except Exception:
            pass

    sniffer = None
    if capture:
        # choose capture iface if not provided
        if capture_iface is None:
            capture_iface = iface
        try:
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
            try:
                with open(logfile, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print('Falha ao atualizar log com captura:', e)
        save_log()


if __name__ == "__main__":
    print('Modo interativo de envio de SYNs (preencha valores)')
    ip_destino = input("Digite o IP de destino: ").strip()
    if not ip_destino:
        print('IP de destino obrigatório')
        raise SystemExit(1)
    porta_destino = int(input("Digite a porta de destino: ").strip() or 0)
    # Escolha entre taxa (pps) ou intervalo
    rate = input("Taxa (pacotes por segundo) (Enter para usar intervalo): ").strip()
    if rate:
        try:
            rate = float(rate)
            intervalo = 1.0 / rate if rate > 0 else 0
        except Exception:
            intervalo = float(input("Erro na taxa, informe intervalo em segundos: "))
    else:
        intervalo = float(input("Digite o intervalo entre envios (em segundos, 0 para sem intervalo): ").strip() or 0)

    count = int(input("Quantidade de pacotes a enviar (0 = indefinido): ").strip() or 0)
    duration = int(input("Duração máxima em segundos (0 = indefinido): ").strip() or 0)
    ip_origem = input("Digite o Ip de origem (ou Enter para automatico): ").strip() or None
    iface = input("Digite o nome da interface (ou Enter para padrão): ").strip() or None
    logfile = input("Nome do arquivo de log (default open_send_log.json): ").strip() or 'open_send_log.json'

    enviar_syn(ip_destino, porta_destino, intervalo=intervalo, count=count, duration=duration, origem_ip=ip_origem, iface=iface, logfile=logfile)