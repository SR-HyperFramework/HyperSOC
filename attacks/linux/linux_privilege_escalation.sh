#!/usr/bin/env bash
set -euo pipefail

logger -t ai-soc-lab "LAB-ONLY privilege-escalation telemetry marker: sudo/su review exercise"
printf 'LAB ONLY marker emitted through logger. Review auth.log/syslog/auditd in Wazuh.\n'
