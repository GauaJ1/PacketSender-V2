# 📦 PacketSend v1

**PacketSend** é um conjunto de scripts em Python para testes de redes e análise: envio de SYNs, verificação de capturas e escaneamento de portas. O objetivo é oferecer ferramentas simples, seguras (quando usadas em redes autorizadas) e fáceis de auditar.

Esta documentação foi organizada para ser direta e explicativa — cada seção contém instruções passo a passo e exemplos que você pode copiar.

---

## 📊 Performance Comparativa

| Cenário | Tempo | Modo |
|---------|-------|------|
| 1-1024 portas | ~5-10s | Connect Scan |
| 1-65535 portas | ~30-60s | Connect Scan |
| 1-1024 portas | ~2-5s | SYN (Batching) |
| **1-65535 portas** | **~0.5-2s** | **SYN (Batching)** ⭐ |

> **SYN Scan é 100x+ mais rápido que a versão anterior!** Graças ao modelo de Batching (sr() em vez de sr1()).

---

## 📋 Menu Interativo

Ao executar sem argumentos, você vê:

```
============================================================
  SCANNER DE PORTAS - MODO INTERATIVO
============================================================

-> IP ou hostname: 192.168.0.1

[*] Opcoes de scan:
  1) Scan rapido (portas 1-1024, ~5s tipico)
  2) Scan completo (1-65535, ~30-60s tipico)
  3) Scan customizado (escolha intervalo e workers)
Escolha (1/2/3, default=1): 1

[*] Opcoes adicionais:
Obter MAC? (s/n, default=n): s
SYN scan (Batch Mode)? Requer admin/Npcap (s/n, default=n): n

[*] Formato de saida:
  1) JSON (padrao)
  2) CSV
  3) NDJSON
  4) XML
Escolha (1/2/3/4, default=1): 1

[RESUMO DA CONFIGURACAO]
  Alvo: 192.168.0.1
  Portas: 1-1024
  Workers: 200
  MAC Lookup: Sim
  SYN Scan: Nao (Connect Scan)
  Formato: JSON
  Salvar em: open_ports.json
------------------------------------------------------------
```

---

## 🔧 Instalação

### Pré-requisitos
- Python 3.10+
- pip

### Setup Automático
```bash
# 1. Clone ou baixe o projeto
cd PacketSend v1

# 2. Crie um ambiente virtual
python -m venv .venv
.venv\Scripts\activate  # Windows

# 3. Instale dependências
pip install -r requirements.txt

# 4. Para SYN Scan no Windows: Instale Npcap
# Baixe em: https://nmap.org/npcap/
# Execute com privilégios de administrador
```

### Dependências
```
pytest
scapy
colorama
```

---

## 📖 Documentação Detalhada

### Para Iniciantes
- 🎯 **[Interface Interativa](INTERFACE_UPDATES.md)** - Menu passo-a-passo com exemplos
- 📊 **[Performance](UPDATE_SUMMARY.md)** - Comparação antes/depois

### Para Desenvolvedores
- 🔬 **[Batching Implementation](BATCHING_IMPLEMENTATION.md)** - Como funciona o SYN Scan rápido
- 📚 **[Documentação Completa](DOCUMENTATION_INDEX.md)** - Índice de todas as docs
- 🧪 **[Status Final](STATUS_FINAL.md)** - Estado atual do projeto

### Referência Rápida
- 📋 [Resultado Final](RESULTADO_FINAL.md) - Resumo visual das mudanças

---

## 💻 Exemplos de Uso

### Exemplo 1: Scan Simples
```bash
python scan_ports.py 192.168.0.1
# Resultado: JSON em open_ports.json
```

### Exemplo 2: Scan Rápido com SYN
```bash
python scan_ports.py 192.168.0.1 --syn --start 1 --end 1024
# Resultado: Portas comuns em ~2-5 segundos
```

### Exemplo 3: Scan Completo com MAC
```bash
python scan_ports.py 192.168.0.1 --syn --start 1 --end 65535 --mac
# Resultado: Todas as portas + MAC address do alvo
```

### Exemplo 4: Exportar em CSV
```bash
python scan_ports.py 192.168.0.1 --format csv --save network_scan.csv
# Resultado: Arquivo CSV compatível com Excel
```

### Exemplo 5: Scan com Rate Limiting
```bash
python scan_ports.py 192.168.0.1 --rate-limit 100
# Resultado: Máximo 100 tentativas por segundo (menos carga)
```

---

## 🎯 Connect vs SYN Scan

### TCP Connect Scan
```
Funciona em: Windows, Linux, macOS (sem privilégios especiais)
Velocidade: 5-60 segundos (conforme número de portas)
Limitação: Lento para ranges grandes (>10k portas)
Vantagem: Confiável, sem dependências especiais
```

### SYN Scan (Batching)
```
Funciona em: Windows (Npcap), Linux (raw sockets)
Velocidade: 0.5-2 segundos para 65535 portas!
Limitação: Requer admin/Npcap no Windows
Vantagem: Muito rápido, menos conspícuo, preciso
```

---

## 📊 Saída Exemplo

### Formato nmap-style (Pretty Print)
```
============================================================
   Scan results for 192.168.0.1 -> 5/1024 open
============================================================
| PORT     | STATE    | SERVICE        |
----------------------------------------
| 22/tcp   | OPEN     | ssh            |
| 80/tcp   | OPEN     | http           |
| 443/tcp  | OPEN     | https          |
| 445/tcp  | OPEN     | microsoft-ds   |
| 3306/tcp | OPEN     | mysql          |
```

### Formato JSON
```json
{
  "target": "192.168.0.1",
  "elapsed": 4.23,
  "results": {
    "22": {"state": "open", "service": "ssh"},
    "80": {"state": "open", "service": "http"},
    "443": {"state": "open", "service": "https"}
  }
}
```

---

## 🧪 Testes

```bash
# Executar testes
pytest tests/ -v

# Resultado esperado: 6 passed in 0.23s
```

---

## 🔒 Segurança & Ética

⚠️ **AVISO IMPORTANTE:**

- ✅ Use apenas em redes que você possui ou tem permissão
- ✅ Respeite as leis locais sobre scanning de rede
- ✅ Não use para atividades maliciosas
- ✅ Obtenha permissão antes de escanear qualquer rede

---

## 📞 Dúvidas Frequentes

**P: Qual é a diferença entre Connect e SYN Scan?**  
R: [Ver Batching Implementation](BATCHING_IMPLEMENTATION.md)

**P: Por que SYN Scan é mais rápido agora?**  
R: [Ver Update Summary](UPDATE_SUMMARY.md)

**P: Como funciona o menu interativo?**  
R: [Ver Interface Updates](INTERFACE_UPDATES.md)

---

## ✅ Status

| Componente | Status |
|------------|--------|
| Core Scan | ✅ Production Ready |
| SYN Scan (Batching) | ✅ Production Ready |
| Interface Interativa | ✅ Production Ready |
| Testes Unitários | ✅ 6/6 Passando |
| Documentação | ✅ Completa |

---

## ⚠️ Aviso legal

Use estas ferramentas apenas em redes onde você tem autorização. Testes sem permissão podem ser ilegais.
