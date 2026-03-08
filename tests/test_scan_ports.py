import json
import os
import socket
import tempfile
import time
import types

import scan_ports


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeSocket:
    """Fake socket para simular diferentes estados de porta."""
    def __init__(self, family, type):
        self.family = family
        self.type = type
        self._timeout = None

    def settimeout(self, t):
        self._timeout = t

    def connect(self, addr):
        port = addr[1]
        if port == 22:
            return           # open
        if port == 23:
            raise ConnectionRefusedError()
        if port == 24:
            raise socket.timeout()
        raise OSError('error')   # error (any other exception)

    def close(self):
        pass


def _run_scan_with_fake(port):
    orig = scan_ports.socket.socket
    try:
        scan_ports.socket.socket = lambda family, type: _FakeSocket(family, type)
        p, status = scan_ports.scan_port('127.0.0.1', port, 0.1)
        return status
    finally:
        scan_ports.socket.socket = orig


# ---------------------------------------------------------------------------
# Testes: get_service_name
# ---------------------------------------------------------------------------

def test_get_service_name_known():
    assert scan_ports.get_service_name(22) == 'ssh'


def test_get_service_name_http():
    assert scan_ports.get_service_name(80) == 'http'


def test_get_service_name_unknown():
    # Porta improvável de ter serviço cadastrado
    result = scan_ports.get_service_name(9)
    # Pode ser 'unknown' ou qualquer string — não deve lançar exceção
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Testes: scan_port
# ---------------------------------------------------------------------------

def test_scan_port_open():
    assert _run_scan_with_fake(22) == 'open'


def test_scan_port_closed():
    assert _run_scan_with_fake(23) == 'closed'


def test_scan_port_filtered():
    assert _run_scan_with_fake(24) == 'filtered'


def test_scan_port_error():
    # Qualquer porta diferente de 22/23/24 dispara OSError → 'error'
    assert _run_scan_with_fake(9999) == 'error'


# ---------------------------------------------------------------------------
# Testes: scan_port_with_retries
# ---------------------------------------------------------------------------

def test_scan_with_retries(monkeypatch):
    calls = {'n': 0}

    def fake_scan(host, port, timeout, family=socket.AF_INET):
        calls['n'] += 1
        if calls['n'] < 3:
            return port, 'filtered'
        return port, 'open'

    monkeypatch.setattr(scan_ports, 'scan_port', fake_scan)
    p, status = scan_ports.scan_port_with_retries(
        '127.0.0.1', 2222, 0.01, socket.AF_INET, max_retries=5, backoff=0.001
    )
    assert status == 'open'
    assert calls['n'] >= 3


# ---------------------------------------------------------------------------
# Testes: TokenBucket
# ---------------------------------------------------------------------------

def test_token_bucket_basic():
    tb = scan_ports.TokenBucket(rate=5, capacity=2)
    assert tb.consume()
    assert tb.consume()
    # Terceiro consume vai esperar tokens, mas deve retornar True
    assert tb.consume()


# ---------------------------------------------------------------------------
# Testes: is_private_ip
# ---------------------------------------------------------------------------

def test_is_private_ip_local():
    assert scan_ports.is_private_ip('192.168.1.1') is True


def test_is_private_ip_loopback():
    assert scan_ports.is_private_ip('127.0.0.1') is True


def test_is_private_ip_public():
    assert scan_ports.is_private_ip('8.8.8.8') is False


def test_is_private_ip_public2():
    assert scan_ports.is_private_ip('1.1.1.1') is False


# ---------------------------------------------------------------------------
# Testes: save_results (JSON e CSV)
# ---------------------------------------------------------------------------

def _make_dummy_args(target='127.0.0.1', start=1, end=10, fmt='json'):
    import argparse
    return argparse.Namespace(
        target=target, target_ip=target, start=start, end=end,
        elapsed=1.23, mac=False, ip_version=4, method='connect', format=fmt
    )


def test_save_results_json():
    results = {
        22: {'state': 'open', 'service': 'ssh'},
        80: {'state': 'open', 'service': 'http'},
    }
    open_ports = [22, 80]
    services_map = {22: 'ssh', 80: 'http'}
    args = _make_dummy_args()

    with tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False, encoding='utf-8') as f:
        fname = f.name
    try:
        scan_ports.save_results(fname, 'json', results, open_ports, services_map, args)
        with open(fname, 'r', encoding='utf-8') as f:
            data = json.load(f)
        assert data['target'] == '127.0.0.1'
        assert any(p['port'] == 22 for p in data['open_ports'])
        assert any(p['port'] == 80 for p in data['open_ports'])
    finally:
        os.unlink(fname)


def test_save_results_csv():
    results = {
        22: {'state': 'open', 'service': 'ssh'},
        23: {'state': 'closed', 'service': 'telnet'},
    }
    open_ports = [22]
    services_map = {22: 'ssh'}
    args = _make_dummy_args(fmt='csv')

    with tempfile.NamedTemporaryFile(suffix='.csv', mode='w', delete=False, encoding='utf-8') as f:
        fname = f.name
    try:
        scan_ports.save_results(fname, 'csv', results, open_ports, services_map, args)
        with open(fname, 'r', encoding='utf-8') as f:
            content = f.read()
        assert 'Port' in content
        assert '22' in content
        assert 'ssh' in content
    finally:
        os.unlink(fname)


def test_save_results_xml():
    results = {80: {'state': 'open', 'service': 'http'}}
    open_ports = [80]
    services_map = {80: 'http'}
    args = _make_dummy_args(fmt='xml')

    with tempfile.NamedTemporaryFile(suffix='.xml', mode='w', delete=False, encoding='utf-8') as f:
        fname = f.name
    try:
        scan_ports.save_results(fname, 'xml', results, open_ports, services_map, args)
        with open(fname, 'r', encoding='utf-8') as f:
            content = f.read()
        assert '<scan' in content
        assert 'number="80"' in content
    finally:
        os.unlink(fname)
