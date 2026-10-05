# SOC console design

The primary job is reviewing an incident against source evidence and internal
context, then making an explicit response decision. The deployment diagram's
ordered workflow is the main organizing element.

Palette: workspace #eef3f8, evidence surface #ffffff, navigation #17364d,
interactive #296dca, context #186d77, warning #a86a12, critical #b63248.
Segoe UI is the interface face; Cascadia Mono is used only for actual log/code
content and identifiers. Typography uses 14/16/20/28 px with left alignment.

Layout: incident queue beside the investigation workspace; the workspace reveals
findings, evidence, internal context, and the graph. The workflow view exposes
each persisted stage. Response controls retain visible approval and execution
states. On mobile the queue precedes the selected case.

```
HyperSOC       Incidents | Intelligence hub | Automation        Account
Live counters                                        Refresh
Incident queue | Case, findings, analyst decision
               | Evidence, context, relationships
               | Response requests and their results
```

Review: a generic KPI-card grid would hide the analyst's task, so counters remain
compact and the selected incident dominates the page. Sequence markers are used
only for the real processing stages. No decorative animation or sample records.
Graph edges are labeled observations; learned predictions have their own label.
Empty states explain which evidence is missing. Keyboard focus and error states
are required; all untrusted text is inserted through textContent.
