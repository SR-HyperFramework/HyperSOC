# Lab Attack Automation (Phase 15)

These scripts are **LAB ONLY** helpers for generating benign telemetry in an
isolated SOC lab. They do not exploit systems, bypass detection, evade controls,
or run destructive payloads.

Use only on systems you own or are explicitly authorized to test.

## Scripts

- `linux/ssh_bruteforce_sim.sh` — prints safe SSH-auth simulation guidance and can
  optionally run a tiny local-only loop against a lab host you provide.
- `linux/linux_privilege_escalation.sh` — emits benign sudo/auditd-style markers.
- `windows/powershell_attack.ps1` — writes a harmless PowerShell telemetry marker.
- `windows/scheduled_task.ps1` — creates/removes an inert lab scheduled-task marker
  when run with `-Create` / `-Cleanup`.
- `windows/registry_persistence.ps1` — writes/removes an inert HKCU lab value.
- `windows/drop_test_file.ps1` — creates a harmless test file for FIM.

Default behavior is dry-run / marker generation. Review each script before use.
