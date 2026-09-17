# Wazuh authentication rule notes

- source: Wazuh
- category: authentication
- technique: T1110

Authentication rules should be interpreted with normalized outcome, user, source
IP, agent, and timestamp fields. Rule level is a prioritization signal, not proof
of maliciousness. Correlation across a bounded time window improves context.
