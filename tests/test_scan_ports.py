import json
import time
import socket
import types
import os

import scan_ports


def test_get_service_name_known():
    assert scan_ports.get_service_name(22) == 'ssh'


class _FakeSocket:
    def __init__(self, family, type):
        self.family = family
        self.type = type
        self._timeout = None

    def settimeout(self, t):
        self._timeout = t

    def connect(self, addr):
        # addr is (host, port) or (host, port, flowinfo, scopeid)
        try:
            port = addr[1]
        except Exception:
            raise Exception('bad addr')
        if port == 22:
            return  # success
        if port == 23:
            raise ConnectionRefusedError()
        if port == 24:
            raise socket.timeout()
        raise Exception()

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


def test_scan_port_open():
    assert _run_scan_with_fake(22) == 'open'


def test_scan_port_closed():
    assert _run_scan_with_fake(23) == 'closed'


def test_scan_port_filtered():
    assert _run_scan_with_fake(24) == 'filtered'


def test_token_bucket_basic():
    tb = scan_ports.TokenBucket(rate=5, capacity=2)
    # consume twice immediately should succeed
    assert tb.consume()
    assert tb.consume()
    # third consume will wait but succeed eventually; we cannot assert time reliably,
    # but calling consume should return True
    assert tb.consume()


def test_scan_with_retries(monkeypatch):
    calls = {'n': 0}

    def fake_scan(host, port, timeout, family=socket.AF_INET):
        calls['n'] += 1
        if calls['n'] < 3:
            return port, 'filtered'
        return port, 'open'

    monkeypatch.setattr(scan_ports, 'scan_port', fake_scan)
    p, status = scan_ports.scan_port_with_retries('127.0.0.1', 2222, 0.01, socket.AF_INET, max_retries=5, backoff=0.001)
    assert status == 'open'
    assert calls['n'] >= 3
