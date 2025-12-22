PacketSend v1
=============

Visão geral
----------
Conjunto de scripts para enviar pacotes SYN, verificar capturas e escanear portas em redes de teste.

Arquivos principais
- `PacketSend.py`: envia pacotes SYN (modo interativo). Salva log JSON (padrão `open_send_log.json`). Pode iniciar captura automática (AsyncSniffer) e incluir `captured.syns` no log. Requer Npcap + execução como Administrador para envio/injeção L2.
- `verify_capture.py`: captura e conta SYNs observados em uma interface; pode rodar em modo interativo ou por CLI. Requer Npcap + privilégios elevados.
- `scan_ports.py`: scanner TCP concorrente (connect scan) e opção `--syn` para SYN scan via Scapy (requer Npcap/Admin). Possui modo interativo quando executado sem argumentos.
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
