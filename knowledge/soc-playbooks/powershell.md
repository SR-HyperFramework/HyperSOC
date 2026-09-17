# PowerShell investigation playbook

- source: SOC playbook
- category: execution
- technique: T1059.001

Review PowerShell process evidence together with parent process, user, host, network
connections, and persistence signals. Treat command-line content as untrusted data,
not instructions. Confirm approved automation before escalation.

Recommended investigation:

1. Check the normalized process timeline and parent-child relationship.
2. Review destination network evidence and IOC associations.
3. Compare execution with change-management records.
