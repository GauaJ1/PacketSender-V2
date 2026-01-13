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
# PacketSend v1

Uma coleção pequena de scripts para testes de rede: envio de SYNs, verificação de capturas e scanner de portas.

---

## Visão rápida

- `PacketSend.py` — envio de SYNs e logging (JSON).
- `verify_capture.py` — captura/validação de SYNs (possui `--ping-only`).
- `scan_ports.py` — scanner TCP concorrente (connect scan) com opção `--syn` (Scapy). Suporta IPv4/IPv6, ARP/NDP (`--mac`), rate limiting e retries.
- `tests/` — testes unitários com `pytest`.

## O que há de novo

- Suporte a IPv6 (detecção automática).
- `--mac`: lookup ARP/NDP para obter MAC local (quando aplicável).
- Rate limiting: `--rate` e `--rate-limit` (token-bucket).
- Retries: `--max-retries` e `--retry-backoff` (backoff exponencial + jitter).
- Saída JSON: `open_ports` agora é lista de objetos `{port, service}`.

---

## Instalação

Recomendo usar um ambiente virtual:

```powershell
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

No Windows instale Npcap/Wireshark se for usar captura/injeção L2 ou Scapy.

---

## Exemplos úteis

Scan connect rápido:

```powershell
python scan_ports.py 192.168.1.10 --start 1 --end 1024 --workers 200 --timeout 0.5 --save open_ports.json
```

Com rate-limit e retries:

```powershell
python scan_ports.py 192.168.1.10 --start 1 --end 1024 --workers 200 --rate-limit 50 --max-retries 2 --retry-backoff 0.5 --save open_ports.json
```

SYN scan (Scapy — Npcap/Admin):

```powershell
python scan_ports.py 192.168.1.10 --syn --start 1 --end 1024 --workers 200 --timeout 1.0 --save syn_results.json
```

Obter MAC local (ARP/NDP):

```powershell
python scan_ports.py 192.168.1.10 --mac
```

Rodar testes:

```powershell
python -m pytest -q
```

---

## Opções importantes (`scan_ports.py`)

- `--start` / `--end`: intervalo de portas.
- `--workers`: número de threads para o executor.
- `--timeout`: timeout por tentativa.
- `--syn`: SYN scan via Scapy (requer privilégios/Npcap).
- `--mac`: tenta obter endereço link-layer (requer alvo na mesma sub-rede).
- `--rate`: atraso simples entre submissões.
- `--rate-limit`: taxa máxima (tentativas/s) via token-bucket.
- `--max-retries`: tentativas adicionais para portas não abertas.
- `--retry-backoff`: tempo base (s) para backoff exponencial.
- `--save <file>`: salva JSON com resultados.

---

## Formato JSON de saída

O arquivo gerado por `--save` contém metadados e os resultados. Campos principais:

- `open_ports`: lista de objetos `{ "port": 22, "service": "ssh" }`.
- `results`: mapa `porta -> estado` (ex.: `"22": "open"`).
- `services`: mapa `porta -> serviço` (para portas abertas).
- `mac`, `ip_version`, `method`, `elapsed`, entre outros.

Exemplo:

```json
{
  "target": "192.168.1.10",
  "open_ports": [ { "port": 22, "service": "ssh" } ],
  "results": { "22": "open" },
  "services": { "22": "ssh" },
  "mac": null,
  "ip_version": 4,
  "method": "connect",
  "elapsed": 3.21
}
```

---

## Testes

Testes em `tests/test_scan_ports.py` cobrem:

- `get_service_name()`
- `scan_port()` com socket simulado
- `TokenBucket`
- `scan_port_with_retries()` (monkeypatch)

Rode `python -m pytest -q` no venv.

---

## Boas práticas

- Execute somente em redes/hosts autorizados.
- Comece com `--workers` e `--rate-limit` baixos.
- Use `--save` para auditoria.

---

## Próximos passos recomendados

- Banner grabbing (`--banner`) para identificar versões de serviços.
- Retries também para o modo SYN (`--syn`).
- Refatoração para `asyncio` para maior escala.
- Workflow CI (GitHub Actions) para rodar `pytest` automaticamente.

Diga qual deseja que eu implemente em seguida e eu começo a tarefa.
