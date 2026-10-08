# SOC console design

The console is a dark "night-ops" workspace built for long monitoring shifts.
The Overview answers "how bad is it right now and what comes next". The
Incidents view remains the place where an analyst reviews a case against source
evidence and internal context, then makes an explicit response decision.

Palette: base #0b0f15, rail #07090d, surface #10161e, raised #151d27,
hairlines #1e2834/#2b3a4b, ink #e4ebf3, muted #7d8da0. Signal mint #3ee2b5 marks
the active, live and primary elements. Severity uses critical #ff4d6a,
high #ff9f43, medium #f2cc4d and low #5d9bff, and these colours mean nothing
else. Segoe UI is the interface face. Cascadia Mono is used for numbers,
identifiers, hosts/IPs, technique IDs and log content.

Layout:

```
┌ rail ─────┐┌ topbar: view title · live counters · UTC clock · Refresh ┐
│ HyperSOC  ││ Threat posture banner (derived from open incidents)       │
│ Overview  ││ KPI strip (6 cells)                                       │
│ Incidents ││ 24h activity chart (2/3)     │ Open severity mix (1/3)    │
│ Hub       ││ Priority queue (2/3)         │ Top MITRE techniques (1/3) │
│ Automation││ Automation pipeline: in-flight jobs per stage + statuses  │
│ account   │└───────────────────────────────────────────────────────────┘
└───────────┘
```

Overview data comes from `/dashboard/summary`, `/dashboard/timeline`,
`/dashboard/mitre`, the latest 100 incidents and the latest 200 workflow jobs.
Any sampling limit is disclosed in the panel. Posture is Critical when an open
critical incident exists, Elevated for open high incidents, Guarded for other
open incidents, and Nominal otherwise. It never triggers a response. Priority
items open the incident in the investigator.

Incidents: a sticky queue sits beside the case, which shows a header, findings,
the analyst decision, collapsible evidence/timeline/context/graph sections and
response approval. Hub and Automation keep their previous structure.

Responsive: below 1100 px the rail collapses to icons. Below 760 px it becomes a
top bar, panels stack and the queue comes before the selected case.

Motion is limited to the live-clock pulse, the critical posture alarm and the
empty-state radar sweep, and all of it is disabled under
`prefers-reduced-motion`. Empty states explain which data is missing. Keyboard
focus uses a 2 px signal outline. All untrusted text is inserted through
`textContent`.
