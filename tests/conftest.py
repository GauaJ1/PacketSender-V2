"""
conftest.py — Adiciona a raiz do projeto ao sys.path
para que `import scan_ports` funcione independente do CWD.
"""
import sys
import os

# Adiciona o diretório raiz (parent de tests/) ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
