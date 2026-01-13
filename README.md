Aqui está a versão atualizada, reestruturada para melhor legibilidade e estilo, formatada inteiramente em Markdown dentro do bloco de código, conforme solicitado.

```markdown
# 📦 PacketSend v1

**PacketSend** é um conjunto de scripts em Python para testes de redes e análise: envio de SYNs, verificação de capturas e escaneamento de portas. O objetivo é oferecer ferramentas simples, seguras (quando usadas em redes autorizadas) e fáceis de auditar.

Esta documentação foi organizada para ser direta e explicativa — cada seção contém instruções passo a passo e exemplos que você pode copiar.

---

## ✨ Funcionalidades principais (resumo)

- `scan_ports.py`: scanner TCP concorrente com suporte a IPv4/IPv6, SYN-scan opcional via Scapy, lookup de MAC (`--mac`), controle de taxa e retries.
- `PacketSend.py`: utilitário interativo para enviar pacotes SYN e gravar logs JSON.
- `verify_capture.py`: valida capturas (conta SYNs recebidos) e pode rodar em modo `--ping-only`.

---

## 🔧 Pré-requisitos e instalação rápida

1. Instale Python 3.8+.
2. Crie e ative um ambiente virtual (recomendado):

```powershell
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
```

3. Instale dependências necessárias (ex.: para usar Scapy ou saída colorida):

```powershell
pip install -r requirements.txt
```

Observações:
- No Windows, instale Npcap se pretende usar captura/injeção em layer 2 ou SYN scan com Scapy.
- Execute scripts que injetam pacotes (SYN/injeção L2) com privilégios de Administrador/Root.

---

## 🧭 Guia de uso — exemplos práticos

1) Scan rápido (connect scan):

```powershell
python scan_ports.py 192.168.1.10 --start 1 --end 1024 --workers 200 --save resultado.json
```

2) Scan com controle de taxa e tentativas (seguro para redes de produção testadas):

```powershell
python scan_ports.py 192.168.1.10 --workers 200 --rate-limit 50 --max-retries 2 --retry-backoff 0.5 --save scan_safe.json
```

3) SYN scan (stealth) — precisa Scapy e privilégios:

```powershell
python scan_ports.py 192.168.1.10 --syn --start 20 --end 80
```

4) Apenas obter MAC local (quando estiver na mesma sub-rede):

```powershell
python scan_ports.py 192.168.1.10 --mac
```

5) Envio interativo de SYNs (use `PacketSend.py`):

```powershell
python PacketSend.py
```

Siga os prompts para configurar IP, porta, taxa (pps) e duração.

---

## 📌 Opções importantes (`scan_ports.py`)

- `target` — IP ou hostname (obrigatório).
- `--start`, `--end` — intervalo de portas.
- `--workers` — número de threads (aumenta velocidade, exige cautela).
- `--timeout` — timeout por tentativa (s).
- `--syn` — ativa SYN scan (requer Scapy/Npcap e privilégios).
- `--mac` — tenta obter endereço link-layer via ARP/NDP (apenas em mesma sub-rede).
- `--rate` — atraso fixo (s) entre submissões de tarefas.
- `--rate-limit` — máximo de tentativas/segundos (token-bucket).
- `--max-retries` — número de tentativas adicionais para portas não abertas.
- `--retry-backoff` — tempo base (s) para backoff exponencial entre tentativas.
- `--pretty` / `--no-pretty` — saída formatada colorida (padrão: `--pretty`).
- `--save <file>` — salva resultados em JSON.

Dica: comece com `--workers` e `--rate-limit` baixos e aumente conforme observa os efeitos na rede.

---

## 📁 Formato do arquivo salvo (`--save`)

O JSON contém metadados do scan e uma lista detalhada de portas abertas. Campos úteis:

- `target`, `target_ip`, `start`, `end` — parâmetros do scan.
- `open_ports` — lista de objetos `{ "port": <n>, "service": "<nome>" }`.
- `results` — mapa `porta -> estado` (ex.: `"22": "open"`).
- `services` — mapa `porta -> serviço` (apenas portas abertas).
- `mac`, `ip_version`, `method`, `elapsed`.

Exemplo curto:

```json
{
  "target": "192.168.1.10",
  "open_ports": [ { "port": 22, "service": "ssh" } ],
  "results": { "22": "open" },
  "mac": null,
  "ip_version": 4,
  "method": "connect",
  "elapsed": 3.21
}
```

---

## 🧪 Testes

Testes automatizados estão em `tests/test_scan_ports.py` e cobrem partes críticas:

- `get_service_name()` — verificação de mapeamento de portas para serviços.
- `TokenBucket` — garante comportamento do limitador de taxa.
- `scan_port()` — testado com um socket falso para evitar conexões reais.
- `scan_port_with_retries()` — testado com `monkeypatch` para simular falhas e sucesso.

Executar testes:

```powershell
python -m pytest -q
```

Explicação simples dos testes: os testes substituem (mock/monkeypatch) partes que fazem I/O (sockets) por versões controladas. Assim validamos a lógica sem tocar a rede.

---

## ⚠️ Aviso legal

Use estas ferramentas apenas em redes onde você tem autorização. Testes sem permissão podem ser ilegais.

```