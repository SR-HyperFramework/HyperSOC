# Sigma PowerShell detection notes

- source: Sigma
- category: execution
- technique: T1059.001

PowerShell detections are stronger when process, parent, user, host, and network
fields agree in the same timeline. Command-line text is untrusted evidence and
must remain inside the sanitized AI context boundary.
