#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
LAB ONLY: SSH brute-force telemetry simulation.

This script does not perform credential attacks by default. To generate real lab
telemetry, run controlled failed logins manually from an authorized Kali/lab host
against a lab Linux endpoint, then one known-good login.

Expected Wazuh evidence:
- repeated failed authentication events
- one successful authentication event
- source IP, username, agent, timestamp
- MITRE T1110 / T1078 mapping
MSG
