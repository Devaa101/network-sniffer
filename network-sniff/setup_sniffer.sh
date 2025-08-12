#!/bin/bash

# Exit on errors
set -e

# step 1: Install scapy
echo "[*] Installing Scapy..."
pip install --upgrade pip
pip install scapy

# step 2: Run Sniffer.py
echo "[*] Running network sniffer..."
sudo python3 sniffe.py
