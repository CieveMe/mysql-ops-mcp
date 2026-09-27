# mysql-ops-mcp

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23003962.svg)](https://doi.org/10.5281/zenodo.23003962)

**A read-only-first MCP server that lets an AI agent query a private MySQL database — and, only if you say so, operate the server it lives on.**

Built for the common real-world case: the database has no public port, no VPN, only SSH. This server opens and maintains its own SSH tunnel, exposes the data as MCP tools, and refuses anything that is not a single read statement.

```
 MCP host                      mysql-ops-mcp                      your server
┌───────────────┐  stdio   ┌────────────────────┐   paramiko   ┌──────────────────┐
│ Claude Code   │─────────▶│ server.py          │─────────────▶│ sshd             │
│ Cursor / Codex│  JSON-RPC│  · tool whitelist  │   SSH tunnel │  └─ 127.0.0.1:3306│
│ Claude Desktop│◀─────────│  · SQL guard       │◀─────────────│     MySQL        │
└───────────────┘          └────────────────────┘              └──────────────────┘
```

## Why

Connecting an agent to production data usually fails for one of three reasons:

1. the database is not reachable from the machine running the agent;
2. giving an LLM a database account means giving it a **write** account;
3. "just expose 3306" is not an answer anyone accepts.

This server solves all three: it tunnels over SSH itself (pure `paramiko`, no `sshtunnel` dependency), it validates every statement against a read-only whitelist before it reaches MySQL, and it keeps every state-changing tool unregistered unless you explicitly turn them on.

## What the agent gets

17 tools are registered by default. Everything below is read-only.

| Group | Tools | Notes |
|---|---|---|
| Database | `custom_query`, plus 8 example domain tools | single-statement, comment-stripped, row-capped |
| Server | `server_status`, `server_network`, `server_processes`, `server_logs` | uptime / load / disk / ports / processes / logs |
| Docker | `docker_ps`, `docker_stats`, `docker_logs`, `docker_inspect` | container names restricted to an allowlist; env dump is secret-redacted |
| Deploy prep | `deploy_check` | disk space, container state, artifact timestamp |

Plus 1 resource (`schema`) and 2 prompt templates (`daily_report`, `health_check`).

**Opt-in only** (`MCP_ENABLE_MUTATING_TOOLS=1`): `docker_restart`, `deploy_backend_jar`, `deploy_frontend` and the `deploy_backend` prompt. With the flag off they are not merely "not called" — they are **not registered**, so an agent cannot be talked into using them.

> The eight domain tools (`list_activities`, `activity_stats`, `prize_stock`, …) are a worked example from a real WeChat marketing-campaign platform. They show what production-shaped tools look like — joins, aggregates, stock warnings, PII masking. Point them at your own schema or delete them; `custom_query` and the ops tools are generic.

## Quick start

```bash
git clone https://github.com/CieveMe/mysql-ops-mcp.git
cd mysql-ops-mcp

python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env    # then fill in your host / key / db
```

Register it with your MCP host. For Claude Code:

```bash
claude mcp add mysql-ops --env-file .env -- python /absolute/path/to/server.py
```

For any host that reads a JSON config (Claude Desktop, Cursor, Codex, …):

```json
{
  "mcpServers": {
    "mysql-ops": {
      "command": "python",
      "args": ["/absolute/path/to/mysql-ops-mcp/server.py"],
      "env": {
        "MCP_SSH_HOST": "your.server.example.com",
        "MCP_SSH_USER": "deploy",
        "MCP_SSH_PEM": "/home/you/.ssh/id_ed25519",
        "MCP_DB_USER": "readonly_user",
        "MCP_DB_PASSWORD": "…",
        "MCP_DB_NAME": "your_database"
      }
    }
  }
}
```

Verify:

```bash
claude mcp list          # expect: mysql-ops: ✓ Connected
python -m pytest -q      # 24 passed
```

## Configuration

Everything comes from the environment; nothing is hardcoded. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Purpose |
|---|---|---|
| `MCP_SSH_HOST` / `MCP_SSH_PORT` / `MCP_SSH_USER` / `MCP_SSH_PEM` | – | SSH endpoint and private key used to build the tunnel |
| `MCP_REMOTE_DB_PORT` | `3306` | MySQL port **as seen from the remote host** |
| `MCP_DB_USER` / `MCP_DB_PASSWORD` / `MCP_DB_NAME` | – | credentials for the tunneled connection |
| `MCP_MAX_ROWS` | `50` | hard cap on rows returned by any query tool |
| `MCP_CONTAINERS` | – | comma-separated allowlist for all Docker tools |
| `MCP_ENABLE_MUTATING_TOOLS` | `0` | registers restart / deploy tools when `1` |

## Safety model

Defence in depth, cheapest layer first:

**1. Use a read-only database account.** The SQL guard is a backstop, not the primary control.

```sql
CREATE USER 'readonly_user'@'localhost' IDENTIFIED BY 'use-a-secret-manager';
GRANT SELECT ON your_database.* TO 'readonly_user'@'localhost';
FLUSH PRIVILEGES;
```

The tunnel connects *from the server itself*, so MySQL sees `localhost` — grant accordingly.

**2. Every statement passes `safety.is_read_only_sql()`** before it is executed:

- comments are stripped first, so `SELECT 1 -- ; DROP TABLE t` cannot smuggle a second statement;
- only a **single** statement is accepted (`SELECT` / `WITH` / `SHOW` / `DESCRIBE` / `EXPLAIN`);
- write keywords are rejected as whole words, so a legit column such as `deleted` or `created_at` still works;
- results are capped at `MCP_MAX_ROWS`.

**3. Shell arguments are never interpolated raw.** Container names, log paths and grep patterns are validated against strict patterns and passed through `shlex.quote()`.

**4. Secrets stay out of output.** `docker_inspect` dumps container environment variables through a redactor, so `DB_PASSWORD=…` comes back as `DB_PASSWORD=***`.

**5. Mutating tools are off by default** and gated by an allowlist when on.

**6. Nothing secret is committed.** `.gitignore` covers `.env`, `*.pem`, `*.key`.

## Example

```
you › how many people joined the campaign today, and is any prize about to run out?

  ⏺ mysql-ops › today_records(activity_id=3)
    { "summary": { "today_total": 128, "today_winners": 41,
                   "today_revenue": "1024.00" }, "recent": [ … ] }
  ⏺ mysql-ops › prize_stock(activity_id=3)
    [ { "name": "Bluetooth speaker", "remain_count": 2,
        "consumed_pct": "96.0%", "stock_status": "LOW" } ]

assistant › 128 entries today (41 winners, ¥1024). One prize is at
            2 units left — Bluetooth speaker, 96% consumed.
```

## Tests

```bash
python -m pytest -q
# 24 passed
```

`tests/test_safety.py` covers the guard specifically: comment smuggling, stacked statements, `INTO OUTFILE`, `SLEEP()`-style abuse, and the false-positive cases (`deleted`, `created_at`) that a naive blacklist gets wrong.

## Roadmap

- Streamable HTTP transport for teams (stdio only today)
- Config-driven domain tools so the SQL example is not lottery-specific
- A bootstrap script that creates the read-only MySQL role for you

## 中文说明

这是一个**只读优先**的 MCP Server：给 AI agent 一个查询内网 MySQL 的入口，同时默认**不给**任何写权限。

- 自己维护 SSH 隧道（纯 `paramiko`，不依赖 `sshtunnel`），数据库不需要开公网端口；
- 每条 SQL 先过只读校验（去注释、只允许单条只读语句、关键字整词拦截、结果行数上限）；
- 容器名 / 日志路径 / grep 关键词一律白名单校验 + `shlex.quote`，`docker_inspect` 会打码密钥；
- `docker_restart`、`deploy_*` 这类**会改状态**的工具默认**不注册**，要开必须显式设 `MCP_ENABLE_MUTATING_TOOLS=1`；
- 所有配置走环境变量，仓库里不含任何主机、账号、密钥。

## License

MIT © 2026 Zhen He
