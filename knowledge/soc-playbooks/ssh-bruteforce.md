# SSH brute-force investigation playbook

- source: SOC playbook
- category: authentication
- technique: T1110

Use when repeated SSH failures share a source IP, host, and user context. Confirm
the time window and whether a successful login follows. Review account criticality,
known scanners, and expected maintenance. Preserve related alert IDs.

Recommended investigation:

1. Validate source-IP reputation and ownership.
2. Review successful sessions and commands for the affected user.
3. Ask the service owner whether access was expected.
4. Consider a human-approved block only after policy checks.
