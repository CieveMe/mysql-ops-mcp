---
title: 'mysql-ops-mcp: a read-only-first MCP server for agent access to SSH-only MySQL databases'
tags:
  - Python
  - MySQL
  - database access
  - large language model agents
  - Model Context Protocol
  - least privilege
authors:
  - name: Zhen He
    orcid: 0009-0009-1526-5793
    affiliation: '1'
affiliations:
  - name: Independent Researcher
    index: 1
date: 28 September 2026
bibliography: paper.bib
---

# Summary

Large language model agents are increasingly used to explore data: an agent inspects a schema, writes
a query, reads the result, and iterates. The awkward part is not the model, it is the plumbing.
Research and operations databases are commonly not reachable from the machine that runs the agent —
there is no public port and no VPN, only SSH — and even when they are reachable, handing an agent a
database account usually means handing it a *write* account, because the privileges a human uses for
maintenance are the ones configured on the account that already exists.

`mysql-ops-mcp` is an implementation of the
[Model Context Protocol](https://modelcontextprotocol.io) [@mcp2024] that addresses both problems. It
opens and maintains its own SSH tunnel with `paramiko` (no `sshtunnel` dependency, no ORM), so the
database keeps its "SSH only" posture, and it exposes the database as MCP tools that an agent can
call from any MCP-capable client. The security posture is expressed in the design rather than in
documentation: every statement passes a read-only guard before it reaches MySQL (single statement
only, comments stripped before keyword matching, leading keyword allowlisted, blocked constructs such
as `INTO OUTFILE` and `SLEEP`, row limit enforced), and every state-changing tool is *not registered
at all* unless the operator sets an explicit environment flag. A tool that is not in the tool list
cannot be talked into existence by a prompt, which is the property the design is built around.

# Statement of need

The software targets two research uses.

**1. Agent-assisted analysis of data the researcher does not control.** Experimental and telemetry
databases are frequently hosted on infrastructure where the researcher has SSH access but no direct
database route, and where an accidental `UPDATE` would destroy a measurement campaign. The server
lets such a database be queried by an agent while the write risk is removed at the tool layer rather
than relying on the agent's good behaviour or on a database account being configured correctly. The
guard is unit-tested in isolation (24 `pytest` cases covering accepted reads and rejected
write/smuggling statements), so a study can state precisely which policy regime was in force instead
of describing a hand-rolled script.

**2. A reference implementation for agent-safety research.** Studies that measure how often agents
violate data-access constraints need implementations with an explicit, auditable policy: a
read-only contract, a documented tool surface (17 tools registered by default; `docker_restart`,
`deploy_backend_jar`, `deploy_frontend` and one prompt template unregistered unless
`MCP_ENABLE_MUTATING_TOOLS=1`), and secret redaction in command output. This server provides that
baseline, and a companion benchmark probes servers of this kind with fixed cases for read-only
violations, dangerous tools registered by default, SQL whitelist bypasses, credential exposure,
prompt-injection surface in tool metadata, and unredacted output.

The alternative implemented by existing MCP database servers is to expose the database directly and
document that the user should not do anything dangerous. That is a reasonable trade-off for a
developer with a disposable database and a poor one for a researcher with a production dataset, which
is the gap this software fills.

# Design notes

Three choices are worth stating because they are the parts a reviewer or a replicator needs to
evaluate.

* **Fail closed on registration.** Dangerous tools are absent from `tools/list`, not blocked at call
  time. Refusing a call leaves the tool visible and describable to the model; removing it removes the
  attack surface entirely.
* **Guard before the network.** The SQL guard is a pure function with no I/O, so it is testable without
  a database and it runs before any connection or tunnel work happens.
* **Redact on the way out.** Tools that read infrastructure state (`docker_inspect`, log readers)
  mask values matching secret patterns, because the transcript the agent produces is itself a place
  where credentials leak.

# Acknowledgements

The author thanks the maintainers of the Model Context Protocol and of the reference servers used
while testing client interoperability. No funding supported this work.

# References
