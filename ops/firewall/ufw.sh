#!/usr/bin/env bash
set -euo pipefail

# Example UFW rules for a public node
# Adjust ports and IP ranges to your environment

ufw default deny incoming
ufw default allow outgoing

# P2P port
ufw allow 9333/tcp

# RPC and indexer should stay local or behind a VPN
ufw allow from 127.0.0.1 to any port 9334 proto tcp
ufw allow from 127.0.0.1 to any port 9337 proto tcp

ufw enable
ufw status
