# mysql-ops-mcp / server.py
# A read-only-first MCP server for AI agents: SQL analytics over a private MySQL
# database (through an auto-managed SSH tunnel) plus optional server/Docker ops.
#
# Everything is configured through environment variables - see .env.example.
# No credentials, hostnames or private keys are stored in this file.

from mcp.server.fastmcp import FastMCP
import pymysql
import paramiko
import json
import os
import re
import shlex
import time
import socket
import threading
from datetime import datetime

from safety import is_read_only_sql, clamp_rows

# ═══════════════════════════════════════
# Configuration (env only - never hardcode secrets)
# ═══════════════════════════════════════


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


SSH_CONFIG = {
    "host": os.environ.get("MCP_SSH_HOST", ""),
    "port": int(os.environ.get("MCP_SSH_PORT", "22")),
    "user": os.environ.get("MCP_SSH_USER", ""),
    "pem_path": os.environ.get("MCP_SSH_PEM", ""),
}

DB_CONFIG = {
    "user": os.environ.get("MCP_DB_USER", ""),
    "password": os.environ.get("MCP_DB_PASSWORD", ""),
    "database": os.environ.get("MCP_DB_NAME", ""),
    "charset": "utf8mb4",
    "connect_timeout": 10,
}

#: Local port the tunnel is exposed on. The database is expected to listen on
#: 127.0.0.1:3306 *on the remote host*; nothing needs to be exposed publicly.
REMOTE_DB_PORT = int(os.environ.get("MCP_REMOTE_DB_PORT", "3306"))

#: Mutating tools (container restart, deploy) are opt-in.
ENABLE_MUTATING_TOOLS = _env_bool("MCP_ENABLE_MUTATING_TOOLS", False)

#: Containers the ops tools are allowed to touch (comma separated).
ALLOWED_CONTAINERS = [
    c.strip()
    for c in os.environ.get("MCP_CONTAINERS", "").split(",")
    if c.strip()
]

#: Max rows any single query tool may return.
MAX_ROWS = int(os.environ.get("MCP_MAX_ROWS", "50"))


def mutating_tool(*args, **kwargs):
    """Register a tool only when MCP_ENABLE_MUTATING_TOOLS is on.

    Read-only deployments therefore expose no way to restart containers or
    overwrite files, even if the agent is talked into trying.
    """
    if ENABLE_MUTATING_TOOLS:
        return mcp.tool(*args, **kwargs)

    def _skip(fn):
        fn.__mcp_disabled__ = True
        return fn

    return _skip


def mutating_prompt(*args, **kwargs):
    """Same idea as mutating_tool(), for prompt templates."""
    if ENABLE_MUTATING_TOOLS:
        return mcp.prompt(*args, **kwargs)

    def _skip(fn):
        fn.__mcp_disabled__ = True
        return fn

    return _skip


_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")

_SECRET_KEY_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)=(\S+)"
)


def redact_secrets(text: str) -> str:
    """Mask ``KEY=value`` pairs whose key looks like a credential."""
    return _SECRET_KEY_RE.sub(lambda m: f"{m.group(1)}=***", text or "")


def _safe_token(value: str, what: str) -> str:
    """Allow only boring identifiers - everything is passed through shlex later."""
    if not _SAFE_TOKEN_RE.match(value or ""):
        raise ValueError(f"unsafe {what}: {value!r}")
    return value


def _safe_container(value: str) -> str:
    name = _safe_token(value, "container name")
    if ALLOWED_CONTAINERS and name not in ALLOWED_CONTAINERS:
        raise ValueError(f"container not in MCP_CONTAINERS: {name}")
    return name


mcp = FastMCP("mysql-ops-mcp")

# ═══════════════════════════════════════
# SSH 连接管理（自动隧道 + 命令执行）
# ═══════════════════════════════════════
_ssh_client: paramiko.SSHClient | None = None
_tunnel_local_port: int | None = None
_tunnel_server: socket.socket | None = None


def _get_pkey():
    return paramiko.RSAKey.from_private_key_file(SSH_CONFIG["pem_path"])


def _get_ssh() -> paramiko.SSHClient:
    """获取 SSH 客户端，自动重连"""
    global _ssh_client
    if _ssh_client:
        t = _ssh_client.get_transport()
        if t and t.is_active():
            return _ssh_client
        try:
            _ssh_client.close()
        except:
            pass

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        SSH_CONFIG["host"],
        port=SSH_CONFIG["port"],
        username=SSH_CONFIG["user"],
        pkey=_get_pkey(),
        timeout=10,
    )
    _ssh_client = client
    return client


def _tunnel_handler(chan, local_sock):
    """双向转发数据"""
    import select
    try:
        while True:
            r, _, _ = select.select([chan, local_sock], [], [], 1.0)
            if chan in r:
                data = chan.recv(65536)
                if not data:
                    break
                local_sock.sendall(data)
            if local_sock in r:
                data = local_sock.recv(65536)
                if not data:
                    break
                chan.sendall(data)
    except (OSError, EOFError):
        pass  # 连接正常关闭
    finally:
        try: chan.close()
        except: pass
        try: local_sock.close()
        except: pass


def _ensure_tunnel() -> int:
    """确保 SSH 隧道存活，返回本地端口号"""
    global _tunnel_local_port, _tunnel_server

    # 检查隧道是否还活着
    if _tunnel_local_port and _tunnel_server:
        try:
            # 快速测试端口是否可连
            test_sock = socket.create_connection(("127.0.0.1", _tunnel_local_port), timeout=2)
            test_sock.close()
            return _tunnel_local_port
        except:
            pass  # 隧道挂了，重建

    # 找一个可用端口
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    local_port = tmp.getsockname()[1]
    tmp.close()

    # 启动本地监听
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", local_port))
    server_sock.listen(5)
    server_sock.settimeout(1.0)

    def accept_loop():
        while True:
            try:
                client_sock, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ssh = _get_ssh()
                transport = ssh.get_transport()
                chan = transport.open_channel(
                    "direct-tcpip",
                    ("127.0.0.1", REMOTE_DB_PORT),
                    client_sock.getpeername(),
                )
                t = threading.Thread(target=_tunnel_handler, args=(chan, client_sock), daemon=True)
                t.start()
            except Exception:
                client_sock.close()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()

    _tunnel_server = server_sock
    _tunnel_local_port = local_port
    return local_port


def _ssh_exec(cmd: str, timeout: int = 15) -> str:
    """在服务器上执行命令，带超时保护"""
    client = _get_ssh()
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out if out else err
    except Exception as e:
        return f"[ERROR] {str(e)}"


# ═══════════════════════════════════════
# MySQL 查询（通过自动 SSH 隧道）
# ═══════════════════════════════════════
def _query(sql: str, params=None) -> list[dict]:
    local_port = _ensure_tunnel()
    conn = pymysql.connect(
        host="127.0.0.1",
        port=local_port,
        cursorclass=pymysql.cursors.DictCursor,
        **DB_CONFIG,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            rows = cur.fetchall()
            for row in rows:
                for k, v in row.items():
                    if isinstance(v, datetime):
                        row[k] = v.strftime("%Y-%m-%d %H:%M:%S")
                    elif isinstance(v, bytes):
                        row[k] = bool(int.from_bytes(v, "big"))
                    elif hasattr(v, "as_integer_ratio") and not isinstance(v, (int, float)):
                        row[k] = int(v) if v == int(v) else float(v)
            return rows
    finally:
        conn.close()


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


# ═══════════════════════════════════════════════════
# PART 1: MySQL 查询 Tools
# ═══════════════════════════════════════════════════

@mcp.tool()
def list_activities() -> str:
    """查询所有抽奖活动列表，含状态、时间、费用、参与人数概览。
    status: 0=草稿 1=进行中 2=已结束"""
    rows = _query("""
        SELECT a.id, a.name, a.status, a.fee,
               a.start_time, a.end_time, a.service_phone,
               (SELECT COUNT(*) FROM lottery_record r
                WHERE r.activity_id = a.id AND r.deleted = 0) as total_records,
               (SELECT COUNT(*) FROM lottery_record r
                WHERE r.activity_id = a.id AND r.deleted = 0 AND r.is_win = 1) as total_winners
        FROM lottery_activity a WHERE a.deleted = 0 ORDER BY a.id DESC
    """)
    return _json(rows)


@mcp.tool()
def activity_stats(activity_id: int) -> str:
    """查询指定活动的详细统计：参与人数、中奖/未中奖、各奖品消耗情况、收入"""
    stats = _query("""
        SELECT COUNT(*) as total_records,
               SUM(CASE WHEN pay_status = 1 THEN 1 ELSE 0 END) as paid_count,
               SUM(CASE WHEN is_win = 1 THEN 1 ELSE 0 END) as winner_count,
               SUM(CASE WHEN is_win = 0 THEN 1 ELSE 0 END) as loser_count,
               COALESCE(SUM(CASE WHEN pay_status = 1 THEN pay_amount ELSE 0 END), 0) as total_revenue,
               COALESCE(SUM(CASE WHEN refund_time IS NOT NULL THEN pay_amount ELSE 0 END), 0) as total_refund,
               SUM(COALESCE(points_earned, 0)) as total_points_given
        FROM lottery_record WHERE activity_id = %s AND deleted = 0
    """, (activity_id,))
    prizes = _query("""
        SELECT name, level, probability, total_count, remain_count,
               (total_count - remain_count) as consumed, type, point_count, cost
        FROM lottery_prize WHERE activity_id = %s AND deleted = 0 ORDER BY level ASC
    """, (activity_id,))
    return _json({"overview": stats[0] if stats else {}, "prizes": prizes})


@mcp.tool()
def today_records(activity_id: int) -> str:
    """查询今天的抽奖数据：摘要 + 最近 15 条记录"""
    summary = _query("""
        SELECT COUNT(*) as today_total,
               SUM(CASE WHEN is_win = 1 THEN 1 ELSE 0 END) as today_winners,
               COALESCE(SUM(CASE WHEN pay_status = 1 THEN pay_amount ELSE 0 END), 0) as today_revenue
        FROM lottery_record
        WHERE activity_id = %s AND deleted = 0 AND DATE(create_time) = CURDATE()
    """, (activity_id,))
    recent = _query("""
        SELECT id, create_time,
               CONCAT(LEFT(COALESCE(nickname, '匿名'), 1), '**') as user_display,
               is_win, prize_name, prize_level, points_earned, pay_status, pay_amount
        FROM lottery_record
        WHERE activity_id = %s AND deleted = 0 AND DATE(create_time) = CURDATE()
        ORDER BY create_time DESC LIMIT 15
    """, (activity_id,))
    return _json({"summary": summary[0] if summary else {}, "recent": recent})


@mcp.tool()
def prize_stock(activity_id: int) -> str:
    """查询指定活动所有奖品的库存。remain_count=-1 表示无限库存"""
    rows = _query("""
        SELECT name, level, total_count, remain_count,
               CASE WHEN remain_count = -1 THEN '无限'
                    ELSE CONCAT(ROUND((total_count - remain_count) / total_count * 100, 1), '%%')
               END as consumed_pct,
               CASE WHEN remain_count != -1 AND remain_count = 0 THEN 'EMPTY'
                    WHEN remain_count != -1 AND remain_count <= 3 THEN 'LOW'
                    ELSE 'OK'
               END as stock_status, type, point_count, cost
        FROM lottery_prize WHERE activity_id = %s AND deleted = 0 ORDER BY level ASC
    """, (activity_id,))
    return _json(rows)


@mcp.tool()
def revenue_by_day(activity_id: int, days: int = 7) -> str:
    """按天统计活动收入（最近N天）"""
    rows = _query("""
        SELECT DATE(create_time) as date, COUNT(*) as order_count,
               SUM(CASE WHEN pay_status = 1 THEN 1 ELSE 0 END) as paid_count,
               COALESCE(SUM(CASE WHEN pay_status = 1 THEN pay_amount ELSE 0 END), 0) as revenue,
               COALESCE(SUM(CASE WHEN refund_time IS NOT NULL THEN pay_amount ELSE 0 END), 0) as refund
        FROM lottery_record
        WHERE activity_id = %s AND deleted = 0
          AND create_time >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
        GROUP BY DATE(create_time) ORDER BY date DESC
    """, (activity_id, days))
    return _json(rows)


@mcp.tool()
def winner_list(activity_id: int, limit: int = 20) -> str:
    """查询中奖记录。receive_status: 0=待领 10=待发货 20=已发货 30=已完成"""
    rows = _query("""
        SELECT id, create_time, nickname, mobile, prize_name, prize_level, prize_cost,
               receive_status, is_local, express_no
        FROM lottery_record
        WHERE activity_id = %s AND is_win = 1 AND deleted = 0
        ORDER BY create_time DESC LIMIT %s
    """, (activity_id, limit))
    return _json(rows)


@mcp.tool()
def points_overview() -> str:
    """查询积分系统概览"""
    user_stats = _query("""
        SELECT COUNT(*) as total_users, SUM(points) as total_points,
               AVG(points) as avg_points, MAX(points) as max_points
        FROM lottery_user_points
    """)
    goods = _query("""
        SELECT id, name, points_price, remain_count, status,
               (SELECT COUNT(*) FROM lottery_point_record r WHERE r.goods_id = g.id) as exchange_count
        FROM lottery_point_goods g WHERE g.deleted = 0 ORDER BY points_price ASC
    """)
    return _json({"user_stats": user_stats[0] if user_stats else {}, "goods": goods})


@mcp.tool()
def custom_query(sql: str) -> str:
    """Run one read-only SQL statement (SELECT / WITH / SHOW / DESCRIBE / EXPLAIN).

    SQL comments are stripped before validation, multiple statements are
    rejected and the result set is capped at MCP_MAX_ROWS rows.
    """
    ok, reason = is_read_only_sql(sql)
    if not ok:
        return f"ERROR: {reason}"
    rows = _query(sql)
    rows, truncated = clamp_rows(rows, MAX_ROWS)
    payload = _json(rows)
    if truncated:
        payload += f"\n(truncated to {MAX_ROWS} rows)"
    return payload


# ═══════════════════════════════════════════════════
# PART 2: 服务器信息查询 Tools
# ═══════════════════════════════════════════════════

@mcp.tool()
def server_status() -> str:
    """查询服务器整体状态：运行时间、CPU、内存、磁盘"""
    info = {}
    info["uptime"] = _ssh_exec("uptime -p")
    info["load"] = _ssh_exec("cat /proc/loadavg")
    info["memory"] = _ssh_exec("free -h | head -3")
    info["disk"] = _ssh_exec("df -h / /opt 2>/dev/null | tail -n +2")
    info["cpu_cores"] = _ssh_exec("nproc")
    return _json(info)


@mcp.tool()
def server_network() -> str:
    """查询服务器网络状态：IP、端口监听、连接数"""
    info = {}
    info["ip"] = _ssh_exec("hostname -I")
    info["listening_ports"] = _ssh_exec("ss -tlnp | head -20")
    info["connection_count"] = _ssh_exec("ss -s | head -5")
    return _json(info)


@mcp.tool()
def server_processes(keyword: str = "") -> str:
    """查看服务器进程，可选关键词过滤（java / mysql / nginx ...）"""
    if keyword:
        try:
            safe_keyword = _safe_token(keyword, "process keyword")
        except ValueError as exc:
            return f"ERROR: {exc}"
        result = _ssh_exec(
            f"ps aux | grep -i {shlex.quote(safe_keyword)} | grep -v grep | head -20"
        )
    else:
        result = _ssh_exec("ps aux --sort=-%mem | head -15")
    return result


@mcp.tool()
def server_logs(log_path: str = "/var/log/syslog", lines: int = 30) -> str:
    """查看服务器系统日志最后 N 行（N 上限 500）"""
    if not _SAFE_PATH_RE.match(log_path or ""):
        return f"ERROR: unsafe log path: {log_path!r}"
    lines = max(1, min(int(lines), 500))
    quoted = shlex.quote(log_path)
    return _ssh_exec(f"tail -n {lines} {quoted} 2>/dev/null || echo 'log not found: {log_path}'")


# ═══════════════════════════════════════════════════
# PART 3: Docker 管理 Tools
# ═══════════════════════════════════════════════════

@mcp.tool()
def docker_ps() -> str:
    """查看所有 Docker 容器状态（运行中+已停止）"""
    return _ssh_exec("docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}'")


@mcp.tool()
def docker_stats() -> str:
    """查看 Docker 容器资源占用（CPU/内存/网络IO）"""
    return _ssh_exec("docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}'")


@mcp.tool()
def docker_logs(container: str = "", lines: int = 50, grep: str = "") -> str:
    """查看 Docker 容器日志（容器名必须在 MCP_CONTAINERS 白名单内）"""
    if not container:
        if not ALLOWED_CONTAINERS:
            return "ERROR: set MCP_CONTAINERS first"
        container = ALLOWED_CONTAINERS[0]
    try:
        name = _safe_container(container)
    except ValueError as exc:
        return f"ERROR: {exc}"
    lines = max(1, min(int(lines), 1000))
    cmd = f"docker logs --tail {lines} {shlex.quote(name)} 2>&1"
    if grep:
        try:
            pattern = _safe_token(grep, "grep pattern")
        except ValueError as exc:
            return f"ERROR: {exc}"
        cmd += f" | grep -i {shlex.quote(pattern)}"
    return _ssh_exec(cmd, timeout=20)


@mutating_tool()
def docker_restart(container: str) -> str:
    """重启指定 Docker 容器（MUTATING - 默认不注册，需 MCP_ENABLE_MUTATING_TOOLS=1）"""
    try:
        name = _safe_container(container)
    except ValueError as exc:
        return f"ERROR: {exc}"
    result = _ssh_exec(f"docker restart {shlex.quote(name)} 2>&1", timeout=30)
    time.sleep(3)
    status = _ssh_exec(
        f"docker ps --filter name={shlex.quote(name)} --format '{{{{.Status}}}}'"
    )
    return f"Restart result:\n{result}\nCurrent status: {status}"


@mcp.tool()
def docker_inspect(container: str = "") -> str:
    """查看容器详情（环境变量里的密钥/token 会被打码）"""
    if not container:
        if not ALLOWED_CONTAINERS:
            return "ERROR: set MCP_CONTAINERS first"
        container = ALLOWED_CONTAINERS[0]
    try:
        name = _safe_container(container)
    except ValueError as exc:
        return f"ERROR: {exc}"
    quoted = shlex.quote(name)
    info = {}
    info["env"] = redact_secrets(_ssh_exec(f"docker exec {quoted} env 2>/dev/null | head -30"))
    info["mounts"] = _ssh_exec(f"docker inspect {quoted} --format '{{{{json .Mounts}}}}' 2>/dev/null")
    info["ports"] = _ssh_exec(f"docker inspect {quoted} --format '{{{{json .NetworkSettings.Ports}}}}' 2>/dev/null")
    info["ip"] = _ssh_exec(f"docker inspect {quoted} --format '{{{{.NetworkSettings.Networks}}}}' 2>/dev/null")
    return _json(info)


# ═══════════════════════════════════════════════════
# PART 4: 部署 Tools
# ═══════════════════════════════════════════════════

@mcp.tool()
def deploy_check() -> str:
    """部署前检查：磁盘、容器状态、产物时间（路径来自 MCP_* 环境变量）"""
    disk_path = os.environ.get("MCP_DISK_PATH", "/")
    if not _SAFE_PATH_RE.match(disk_path):
        return f"ERROR: unsafe MCP_DISK_PATH: {disk_path!r}"
    checks = {}
    checks["disk_free"] = _ssh_exec(f"df -h {shlex.quote(disk_path)} | tail -1")
    checks["containers"] = _ssh_exec("docker ps --format '{{.Names}}: {{.Status}}'")
    jar_path = os.environ.get("MCP_REMOTE_JAR_PATH", "")
    if jar_path and _SAFE_PATH_RE.match(jar_path):
        quoted = shlex.quote(jar_path)
        checks["artifact_size"] = _ssh_exec(f"ls -lh {quoted} 2>/dev/null | awk '{{print $5}}'")
        checks["artifact_date"] = _ssh_exec(f"stat -c '%y' {quoted} 2>/dev/null | cut -d. -f1")
    return _json(checks)


@mutating_tool()
def deploy_backend_jar(local_jar_path: str) -> str:
    """上传并部署后端 JAR。流程：停容器→上传JAR→启容器→健康检查。
    local_jar_path: 本地 JAR 的绝对路径（MUTATING - 默认不注册）"""
    remote_path = os.environ.get("MCP_REMOTE_JAR_PATH", "")
    service = os.environ.get("MCP_BACKEND_SERVICE", "server")
    compose_dir = os.environ.get("MCP_COMPOSE_DIR", "")
    if not remote_path or not compose_dir:
        return "ERROR: set MCP_REMOTE_JAR_PATH and MCP_COMPOSE_DIR first"
    cd = shlex.quote(compose_dir)
    steps = []

    # Step 1: 停容器
    steps.append("1. Stopping server...")
    steps.append(_ssh_exec(f"cd {cd} && docker compose stop {shlex.quote(service)} 2>&1", timeout=30))

    # Step 2: 上传 JAR（通过 paramiko SFTP）
    steps.append("2. Uploading JAR...")
    try:
        client = _get_ssh()
        sftp = client.open_sftp()
        sftp.put(local_jar_path, remote_path)
        sftp.close()
        steps.append(f"   Uploaded: {local_jar_path} -> {remote_path}")
    except Exception as e:
        steps.append(f"   UPLOAD FAILED: {e}")
        # 尝试重启
        _ssh_exec(f"cd {cd} && docker compose start {shlex.quote(service)} 2>&1", timeout=30)
        return "\n".join(steps) + "\n\nServer restarted with old JAR."

    # Step 3: 启动容器
    steps.append("3. Starting server...")
    steps.append(_ssh_exec(f"cd {cd} && docker compose start {shlex.quote(service)} 2>&1", timeout=30))

    # Step 4: 等待健康检查
    steps.append("4. Waiting for health check (15s)...")
    time.sleep(15)
    health_url = os.environ.get("MCP_HEALTH_URL", "http://localhost:48080/actuator/health")
    if not _SAFE_PATH_RE.match("/" + health_url.split("//", 1)[-1]):
        return "\n".join(steps) + "\nERROR: unsafe MCP_HEALTH_URL"
    health = _ssh_exec(
        f"curl -s -o /dev/null -w '%{{http_code}}' {shlex.quote(health_url)} 2>/dev/null || echo 'no-response'"
    )
    steps.append(f"   Health: {health}")

    return "\n".join(steps)


@mutating_tool()
def deploy_frontend(local_dir: str, target: str = "admin") -> str:
    """上传并部署前端目录。target 必须是 MCP_FRONTEND_TARGETS 里配置过的名字（MUTATING）"""
    remote_map = {}
    for pair in os.environ.get("MCP_FRONTEND_TARGETS", "").split(","):
        if "=" in pair:
            key, _, value = pair.partition("=")
            remote_map[key.strip()] = value.strip()
    if target not in remote_map:
        return f"ERROR: target must be one of {sorted(remote_map)} (set MCP_FRONTEND_TARGETS)"
    remote = remote_map[target]
    reload_cmd = os.environ.get("MCP_NGINX_RELOAD_CMD", "")

    steps = []
    # 备份
    steps.append(f"1. Backing up {remote}...")
    steps.append(_ssh_exec(f"cp -r {remote} {remote}.bak.$(date +%Y%m%d%H%M) 2>&1"))

    # 上传（通过 SFTP 递归）
    steps.append(f"2. Uploading {local_dir} -> {remote}...")
    try:
        client = _get_ssh()
        sftp = client.open_sftp()
        import os as _os
        for root, dirs, files in _os.walk(local_dir):
            for f in files:
                local_f = _os.path.join(root, f)
                rel = _os.path.relpath(local_f, local_dir).replace("\\", "/")
                remote_f = f"{remote}/{rel}"
                # 确保远程目录存在
                remote_dir = "/".join(remote_f.split("/")[:-1])
                _ssh_exec(f"mkdir -p {remote_dir}")
                sftp.put(local_f, remote_f)
        sftp.close()
        steps.append("   Upload complete")
    except Exception as e:
        steps.append(f"   UPLOAD FAILED: {e}")
        return "\n".join(steps)

    # 重载 nginx
    if reload_cmd:
        steps.append("3. Reloading nginx...")
        steps.append(_ssh_exec(reload_cmd))
    return "\n".join(steps)


# ═══════════════════════════════════════════════════
# Resource & Prompts
# ═══════════════════════════════════════════════════

@mcp.resource("lottery://schema")
def get_schema() -> str:
    """数据库核心表结构"""
    return """
lottery_activity: id, name, status(0草稿/1进行中/2已结束), fee, start_time, end_time, rule_desc(JSON), service_phone, delivery_days
lottery_prize: id, activity_id, name, level, probability, total_count, remain_count(-1=无限), type(1实物/2虚拟), point_count, cost, pic_url
lottery_record: id, activity_id, user_id, mobile, nickname, order_no, pay_status(0/1), pay_amount, pay_time, wx_transaction_id, is_win, prize_id, prize_name, prize_level, prize_cost, points_earned, receive_status(0待领/10待发/20已发/30完成), is_local, address fields, express_no, refund_time, wx_refund_id, openid
lottery_user_points: user_id, points
lottery_point_goods: id, name, points_price, remain_count, status
lottery_point_record: user_id, goods_id, create_time
All tables have: deleted(bit), tenant_id, create_time, update_time
Note: pay_amount unit is YUAN, not fen.
"""


@mcp.resource("lottery://server-info")
def get_server_info() -> str:
    """部署拓扑说明（不含真实主机名/IP，全部来自环境变量）"""
    compose_dir = os.environ.get("MCP_COMPOSE_DIR", "<MCP_COMPOSE_DIR>")
    jar_path = os.environ.get("MCP_REMOTE_JAR_PATH", "<MCP_REMOTE_JAR_PATH>")
    containers = ", ".join(ALLOWED_CONTAINERS) or "<MCP_CONTAINERS>"
    return f"""
Docker Compose project: {compose_dir or '<MCP_COMPOSE_DIR>'}
Containers (allowlisted): {containers}
Backend artifact: {jar_path}
Database access: SSH tunnel -> 127.0.0.1:{REMOTE_DB_PORT} on the remote host
Mutating tools enabled: {ENABLE_MUTATING_TOOLS}
"""


@mcp.prompt()
def daily_report(activity_id: str) -> str:
    """生成每日运营报告"""
    return f"""请为活动 {activity_id} 生成今日运营报告：
1. 调用 today_records(activity_id={activity_id})
2. 调用 prize_stock(activity_id={activity_id})
3. 调用 revenue_by_day(activity_id={activity_id}, days=1)
输出格式：今日参与/中奖/收入/库存预警/待发货"""


@mcp.prompt()
def health_check() -> str:
    """系统全面健康检查"""
    return """执行全面健康检查：
1. server_status() - 服务器资源
2. docker_ps() - 容器状态
3. docker_stats() - 资源占用
4. list_activities() - 活动状态
5. 对进行中的活动检查 prize_stock()
汇报: OK/WARNING/ERROR 项"""


@mutating_prompt()
def deploy_backend() -> str:
    """后端部署完整流程（MUTATING - 默认不注册）"""
    return """执行后端部署：
1. deploy_check() - 部署前检查
2. 确认磁盘空间和容器状态正常
3. 询问用户本地 JAR 路径
4. deploy_backend_jar(local_jar_path) - 执行部署
5. docker_logs(container=..., lines=20) - 检查启动日志
6. 确认无 ERROR 后报告完成"""


# ═══════════════════════════════════════
# 清理 & 启动
# ═══════════════════════════════════════
import atexit

def _cleanup():
    global _tunnel_server, _ssh_client
    if _tunnel_server:
        try: _tunnel_server.close()
        except: pass
    if _ssh_client:
        try: _ssh_client.close()
        except: pass

atexit.register(_cleanup)

if __name__ == "__main__":
    mcp.run()
