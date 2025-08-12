#!/bin/bash

# Exit on errors
set -e

# step 1: Create virtual environment if not exists
if [ ! -d "venv" ]; then
        echo "[*] Creating Python virtual environment..."
        Python3 -m venv myvenv
fi

# step 2: Activate the virtual environment
echo "[*] Activating virtual environment..."
source myvenv/bin/activate

# step 3: Install scapy
echo "[*] Installing Scapy..."
pip install --upgrade pip
pip install scapy

# step 4: Run Sniffer.py
echo "[*] Running network sniffer..."
sudo python3 sniffe.py
