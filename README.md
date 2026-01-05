PacketSend v1
=============

Visão geral
----------
Conjunto de scripts para enviar pacotes SYN, verificar capturas e escanear portas em redes de teste.

Arquivos principais
- `PacketSend.py`: envia pacotes SYN (modo interativo). Salva log JSON (padrão `open_send_log.json`). Pode iniciar captura automática (AsyncSniffer) e incluir `captured.syns` no log. Requer Npcap + execução como Administrador para envio/injeção L2.
- `verify_capture.py`: captura e conta SYNs observados em uma interface; pode rodar em modo interativo ou por CLI. Requer Npcap + privilégios elevados.
- `scan_ports.py`: scanner TCP concorrente (connect scan) e opção `--syn` para SYN scan via Scapy (requer Npcap/Admin). Possui modo interativo quando executado sem argumentos.
- `scan_ports.py`: scanner TCP concorrente (connect scan) e opções `--syn` para SYN scan via Scapy (requer Npcap/Admin) e `--mac` para obter endereço MAC via ARP (rede local). Possui modo interativo quando executado sem argumentos.
- `open_send_log.json`: gerado por `PacketSend.py` (registro dos envios e quantidade capturada).
- `open_ports.json`: pode ser gerado por `scan_ports.py` com a opção `--save` (resultados do scan).

Pré-requisitos
````markdown
PacketSend v1
=============

Visão geral
----------
Conjunto de scripts para enviar pacotes SYN, verificar capturas e escanear portas em redes de teste.

Arquivos principais
- `PacketSend.py`: envia pacotes SYN (modo interativo). Salva log JSON (padrão `open_send_log.json`). Pode iniciar captura automática (AsyncSniffer) e incluir `captured.syns` no log. Requer Npcap + execução como Administrador para envio/injeção L2.
- `verify_capture.py`: captura e conta SYNs observados em uma interface; pode rodar em modo interativo ou por CLI. Requer Npcap + privilégios elevados.
- `scan_ports.py`: scanner TCP concorrente (connect scan) e opção `--syn` para SYN scan via Scapy (requer Npcap/Admin). Possui modo interativo quando executado sem argumentos.
- `scan_ports.py`: scanner TCP concorrente (connect scan) e opções `--syn` para SYN scan via Scapy (requer Npcap/Admin) e `--mac` para obter endereço MAC via ARP (rede local). Possui modo interativo quando executado sem argumentos.
- `open_send_log.json`: gerado por `PacketSend.py` (registro dos envios e quantidade capturada).
- `open_ports.json`: pode ser gerado por `scan_ports.py` com a opção `--save` (resultados do scan).

Pré-requisitos
- Python 3.8+ (virtualenv recomendado)
- Dependências do Python: `scapy` (instale no seu venv: `pip install scapy`) — necessário para `PacketSend.py`, `verify_capture.py` e `--syn` em `scan_ports.py`.
- Npcap (Windows) para captura/injeção em layer 2. Ao instalar, marque a opção "WinPcap API-compatible Mode" se houver necessidade de compatibilidade.
- Executar o terminal/VSCode como Administrador para injeção/captura L2.
- (Opcional) Wireshark/tshark para inspeção: `tshark` fica disponível quando instalar Wireshark.

Como instalar Npcap (resumo)
```powershell
# usar o instalador oficial do Npcap (baixar do site oficial)
# ou instalar Wireshark via winget (inclui Npcap) e selecione compatibilidade WinPcap durante a instalação
winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
```

Executando os scripts (exemplos)

1) `PacketSend.py` (modo interativo)
```powershell
cd 'C:\Users\Usuario\Pictures\PacketSend v1'
& '.\.venv\Scripts\Activate.ps1'   # se estiver usando venv
python PacketSend.py
# Responda os prompts: IP, porta, taxa/intervalo, quantidade, duração, iface e nome do log
```
- Dica: para um teste rápido escolha `count=10` e `rate=1` (1 pps). Rode `verify_capture.py` ou Wireshark simultaneamente para confirmar a captura.

2) `verify_capture.py`
```powershell
# modo CLI
python verify_capture.py --dest 192.168.92.212 --iface "\\Device\\NPF_{...}" --timeout 10
# ou modo interativo
python verify_capture.py
```
Filtro usado internamente: `tcp and dst host <DEST>` — ideal para ver os SYNs que chegam ao destino.

3) `scan_ports.py` (connect scan, rápido e sem Npcap)
```powershell
# modo interativo
python scan_ports.py
# CLI exemplo
python scan_ports.py 192.168.92.212 --start 1 --end 1024 --workers 200 --timeout 0.5 --save open_ports.json
```

3b) `scan_ports.py` (ARP lookup — obter MAC do alvo na rede local)
```powershell
# Obter apenas o MAC (tenta popular a cache ARP antes de consultar):
python scan_ports.py 192.168.1.10 --mac

# Combinar com scan e salvar resultado (incluirá o campo `mac` no JSON):
python scan_ports.py 192.168.1.10 --start 1 --end 1024 --workers 200 --timeout 0.5 --mac --save open_ports_with_mac.json
```
Nota: a opção `--mac` faz um ping rápido para popular a cache ARP e então consulta a tabela ARP local (`arp -a` no Windows, `ip neigh` / `arp -n` em Unix). Funciona somente em hosts na mesma sub-rede/segmento (rede local). Se o alvo estiver fora da LAN ou a entrada ARP estiver filtrada/ausente, o MAC pode não ser encontrado.
4) `scan_ports.py` (SYN scan com Scapy — requer Npcap/Admin)
```powershell
python scan_ports.py 192.168.92.212 --start 1 --end 1024 --syn --workers 200 --timeout 1.0 --save syn_results.json
```

Verificação com tshark/Wireshark
- Lista interfaces:
```powershell
tshark -D
```
- Capturar e mostrar SYNs para destino (linha de comando):
```powershell
tshark -i "Ethernet" -Y "tcp.flags.syn==1 && ip.dst==192.168.92.212" -c 50
```

Resolução de problemas comuns
- Erro "TCP data cannot be sent over raw socket" ou "winpcap is not installed": instale Npcap e execute como Administrador; defina `conf.use_pcap = True` (feito nos scripts).
- `tshark` não encontrado no PATH: adicione `C:\Program Files\Wireshark` ao `PATH` ou execute com caminho completo.
- JSON serializable errors no log: `PacketSend.py` já converte a interface para string antes de gravar.

Boas práticas e segurança
- Execute somente em redes e hosts que você possui ou para os quais tem autorização explícita.
- Evite aumentar `--workers` e taxas sem controle — isso pode causar problemas na rede e é potencialmente ilegal em redes de terceiros.
- Use ambiente de teste (máquinas virtuais ou rede isolada) para experimentos de alto volume.

Próximos passos sugeridos
- Se quiser, eu posso:
  - transformar `PacketSend.py` em uma CLI completa (argumentos `--count --rate --capture`),
  - adicionar validação de entradas e mensagens mais descritivas,
  - gerar exemplos de execução em um `examples/` ou criar uma task do VSCode para rodar os scripts.


---
Se quiser que eu adicione a opção CLI no `PacketSend.py` agora, diga "Adicionar CLI" e eu implemento. Caso contrário, posso criar exemplos passo-a-passo ou incorporar validação extra.

## Alterações e explicações (detalhado)

Resumo das alterações recentes e como cada recurso funciona — útil para testar e entender o comportamento.

- `PacketSend.py` (Suporte IPv6)
  - O que foi feito: o script agora resolve o destino antes de construir o pacote e seleciona `IPv6()` ou `IP()` conforme a família do endereço. Os logs incluem `ip_version` em cada entrada/arquivo JSON.
  - Como funciona: ao receber um hostname ou IP, o script usa `socket.getaddrinfo()` para obter o endereço resolvido e a família (IPv4/IPv6). Em IPv6 ele constrói pacotes com `IPv6(dst=...) / TCP(...)` e os envia com `send()` (L3) ou `sendp()` (L2) quando uma interface L2 é pedida.
  - Teste rápido: execute `python PacketSend.py` e informe um endereço IPv6 local ou hostname que resolva para IPv6; abra o JSON de log e verifique `ip_version`.

- `scan_ports.py` (IPv6 + `--mac`)
  - O que foi feito: resolução com `getaddrinfo()` para suportar IPv4/IPv6; `scan_port()` é consciente da família (AF_INET/AF_INET6) e o SYN scan usa `IPv6()` quando aplicável. Adicionada a opção `--mac` para tentar obter o endereço link-layer via ARP (IPv4).
  - Como funciona: para IPv6 o scanner cria sockets AF_INET6 para connect-scan e usa pacotes Scapy `IPv6()/TCP()` para SYN scan. `--mac` faz um ping curto e consulta a tabela ARP/local neighbor — válido apenas para IPv4 (o script avisa se você usar `--mac` com um alvo IPv6).
  - Saída JSON (`--save`): ao usar `--save` o script grava um JSON com metadados do scan. O campo `open_ports` agora é uma lista de objetos detalhados no formato `[{"port": <porta>, "service": "<nome>"}, ...]`. O arquivo também inclui um mapeamento `results` (porta -> estado), `services` (serviços para portas abertas), e campos auxiliares como `mac` (se `--mac` foi usado), `ip_version` (4 ou 6) e `method` (por exemplo, `"syn"` para SYN scan).

    Exemplo de saída (trecho):

    ```json
    {
      "target": "192.168.1.10",
      "open_ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
      "results": {"22": "open", "80": "open", "23": "closed"},
      "services": {"22": "ssh", "80": "http"},
      "mac": "01:23:45:67:89:ab",
      "ip_version": 4,
      "method": "syn"
    }
    ```
  - Teste rápido (IPv6 SYN scan — precisa Scapy + privilégios):
    - `python scan_ports.py 2001:db8::1 --start 22 --end 25 --syn --workers 50 --save results_ipv6.json`

- `verify_capture.py` (IPv6, `--mac`, `--ping-only`)
  - O que foi feito: o script resolve o destino para um IP canônico (`resolved_dest`) e aceita IPv6 em capture e filtro BPF (`ip6 and tcp ...`). Adicionados `--mac` (tenta ARP ou NDP/neighbor lookup) e `--ping-only` (executa ping(s) sem precisar de interface).
  - Como funciona:
    - Captura: o filtro BPF usa `ip6` quando apropriado; o handler confirma `TCP` e a condição SYN sem ACK, e compara o `dst` do pacote com o IP resolvido.
    - `--mac`: em IPv4 faz `ping` e consulta `arp -a`/`ip neigh`; em IPv6 faz `ping` e consulta `ip -6 neigh` ou `netsh interface ipv6 show neighbors` (Windows). Depende da cache local e só funciona para hosts na mesma sub-rede.
    - `--ping-only`: executa `ping` adequadamente (Windows/Unix) — útil quando não há interface de captura disponível.
  - Testes rápidos:
    - `python verify_capture.py --dest 192.168.1.10 --ping-only --ping-count 3`
    - `python verify_capture.py --dest 2001:db8::1 --ping-only --ping-count 2`
    - `python verify_capture.py --dest 192.168.1.10 --iface "\\Device\\NPF_{...}" --timeout 10 --mac`

Observações e limitações
- `--mac`/NDP: só confiável na mesma sub-rede/link; NDP/neighbor lookup varia por SO e saída pode depender do idioma do sistema.
- Privilégios: captura com Scapy/AsyncSniffer e SYN scans requerem drivers/privilégios (Npcap + execução como Administrador no Windows).
- Segurança/uso: execute apenas em redes/hosts autorizados.

Quer que eu adicione uma seção separada "Comandos por SO" com exemplos específicos para Windows e Linux? 
````
