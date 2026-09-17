# Persistence investigation playbook

- source: SOC playbook
- category: persistence
- technique: T1053

Use when process execution is correlated with scheduled tasks, registry run keys, or
other persistence indicators. Confirm the creator, target account, execution path,
and timeline before recommending containment.

Recommended investigation:

1. Identify the first persistence event and related process.
2. Validate whether the task or registry change is approved.
3. Review affected user and host activity for follow-on execution.
