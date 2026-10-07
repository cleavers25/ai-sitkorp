"""Server health & security checks over SSH (PRD 9.1, 11).

Every command below is a fixed string. Nothing from the asset record, the LLM or the target
is interpolated into these commands, so they cannot be used for injection.
Parsing is split into pure functions so it can be tested without a server.
"""

import re
import time
from collections.abc import Awaitable, Callable

from app.assessment.types import CheckResult, Runner, clip, error, issue, passed, skipped
from app.core.enums import FindingCategory as C
from app.core.enums import Severity as S

DF_EXCLUDES = "-x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs"

CMD_LOAD = "cat /proc/loadavg; nproc; cat /proc/uptime"
CMD_MEMINFO = "cat /proc/meminfo"
CMD_DISK = f"df -P {DF_EXCLUDES}"
CMD_INODE = f"df -P -i {DF_EXCLUDES}"
CMD_FAILED_UNITS = "systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null || echo __NO_SYSTEMD__"
CMD_LISTEN = "ss -H -tuln 2>/dev/null || echo __NO_SS__"
CMD_NTP = "timedatectl show -p NTPSynchronized --value 2>/dev/null || echo __UNKNOWN__"
CMD_REBOOT = "test -f /var/run/reboot-required && echo yes || echo no"
CMD_SSHD = ("sshd -T 2>/dev/null || { echo __FILES__; "
            "cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null; cat /etc/ssh/sshd_config 2>/dev/null; }")
CMD_PS = "ps -eo pid=,user=,pcpu=,pmem=,args= --sort=-pcpu 2>/dev/null | head -n 300"

MINER_NAMES = re.compile(
    r"\b(xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|nbminer|t-rex|lolminer|phoenixminer|kthreaddi)\b",
    re.I,
)
SUSPICIOUS_EXEC_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB"}


# --- pure parsers / evaluators -------------------------------------------

def eval_load(out: str) -> list[CheckResult]:
    lines = out.split()
    load1, load5, load15 = (float(x) for x in lines[:3])
    cpus = int(lines[5])
    uptime_days = float(lines[6]) / 86400
    ratio = load5 / max(cpus, 1)
    ev = {"load1": load1, "load5": load5, "load15": load15, "cpus": cpus, "uptime_days": round(uptime_days, 1)}
    value = f"load5 {load5:.2f} / {cpus} CPU"
    if ratio >= 2:
        return [issue("cpu_load", C.SYSTEM, "Beban CPU sangat tinggi", S.MEDIUM, value=value, evidence=ev,
                      recommendation="Periksa proses dengan CPU tertinggi (lihat check proses) dan kapasitas server.")]
    if ratio >= 1.5:
        return [issue("cpu_load", C.SYSTEM, "Beban CPU tinggi", S.LOW, value=value, evidence=ev,
                      recommendation="Pantau tren beban; pertimbangkan penambahan CPU bila terus tinggi.")]
    return [passed("cpu_load", C.SYSTEM, "Beban CPU normal", value=value, evidence=ev)]


def eval_memory(out: str) -> list[CheckResult]:
    info = {}
    for line in out.splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m:
            info[m.group(1)] = int(m.group(2))
    total = info["MemTotal"]
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    pct_avail = avail / total * 100
    swap_total, swap_free = info.get("SwapTotal", 0), info.get("SwapFree", 0)
    ev = {"total_mb": total // 1024, "available_mb": avail // 1024,
          "swap_used_mb": (swap_total - swap_free) // 1024}
    value = f"{pct_avail:.0f}% tersedia"
    if pct_avail < 5:
        return [issue("memory", C.SYSTEM, "Memori hampir habis", S.HIGH, value=value, evidence=ev,
                      recommendation="Periksa proses dengan pemakaian memori terbesar; risiko OOM killer.")]
    if pct_avail < 10:
        return [issue("memory", C.SYSTEM, "Memori tersedia rendah", S.MEDIUM, value=value, evidence=ev,
                      recommendation="Pantau pemakaian memori dan pertimbangkan penambahan RAM.")]
    return [passed("memory", C.SYSTEM, "Memori cukup", value=value, evidence=ev)]


PSEUDO_MOUNTS = ("/etc/", "/run", "/dev", "/proc", "/sys")


def _parse_df(out: str) -> list[tuple[str, int, str]]:
    """Real filesystems only: drops container bind-mounts (/etc/hosts…) and repeat mounts of one device."""
    rows: dict[str, tuple[str, int, str]] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6 or not parts[4].endswith("%") or parts[4] == "-%":
            continue
        fs, pct, mount = parts[0], int(parts[4].rstrip("%")), parts[5]
        if mount.startswith(PSEUDO_MOUNTS):
            continue
        if fs not in rows or len(mount) < len(rows[fs][2]):
            rows[fs] = (fs, pct, mount)
    return list(rows.values())


def eval_df(out: str, *, inode: bool) -> list[CheckResult]:
    check = "inode_usage" if inode else "disk_usage"
    what = "Inode" if inode else "Disk"
    results = []
    for fs, pct, mount in _parse_df(out):
        ev = {"filesystem": fs, "mount": mount, "used_percent": pct}
        value = f"{pct}%"
        rec = ("Bersihkan file kecil yang menumpuk (cache, session, mail queue)." if inode
               else "Bersihkan log/backup lama atau tambah kapasitas disk.")
        if pct >= 90:
            results.append(issue(check, C.STORAGE, f"{what} {mount} kritis ({pct}%)", S.HIGH,
                                 value=value, target=mount, evidence=ev, recommendation=rec))
        elif pct >= 80:
            results.append(issue(check, C.STORAGE, f"{what} {mount} di atas 80% ({pct}%)", S.MEDIUM,
                                 value=value, target=mount, evidence=ev, recommendation=rec))
        else:
            results.append(passed(check, C.STORAGE, f"{what} {mount} normal", value=value, target=mount, evidence=ev))
    return results or [skipped(check, C.STORAGE, "Tidak ada filesystem yang bisa dibaca")]


def eval_failed_units(out: str) -> list[CheckResult]:
    if "__NO_SYSTEMD__" in out:
        return [skipped("failed_services", C.SERVICE, "systemd tidak tersedia")]
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    if units:
        return [issue("failed_services", C.SERVICE, f"{len(units)} service systemd dalam status failed", S.MEDIUM,
                      value=", ".join(units)[:255], evidence={"units": units},
                      recommendation="Periksa `systemctl status <unit>` dan `journalctl -u <unit>`.")]
    return [passed("failed_services", C.SERVICE, "Tidak ada service yang gagal")]


def eval_listen(out: str) -> list[CheckResult]:
    if "__NO_SS__" in out:
        return [skipped("exposed_db_ports", C.NETWORK, "Perintah ss tidak tersedia")]
    listening: list[str] = []
    exposed: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        listening.append(f"{parts[0]} {local}")
        public = addr in ("0.0.0.0", "*", "[::]", "::")
        if public and int(port) in DB_PORTS and parts[0].startswith("tcp"):
            exposed.append(f"{DB_PORTS[int(port)]} ({local})")
    ev = {"listening": sorted(set(listening))[:100]}
    if exposed:
        return [issue("exposed_db_ports", C.NETWORK, "Port database terbuka di semua interface", S.MEDIUM,
                      value=", ".join(exposed)[:255], evidence=ev,
                      recommendation="Bind service database ke 127.0.0.1/jaringan privat, atau batasi dengan firewall.")]
    return [passed("exposed_db_ports", C.NETWORK, "Tidak ada port database terbuka ke publik", evidence=ev)]


def eval_ntp(out: str) -> list[CheckResult]:
    v = out.strip()
    if v == "yes":
        return [passed("ntp_sync", C.SYSTEM, "Waktu tersinkron (NTP)")]
    if v == "no":
        return [issue("ntp_sync", C.SYSTEM, "Waktu server tidak tersinkron NTP", S.LOW,
                      recommendation="Aktifkan systemd-timesyncd/chrony; waktu yang salah merusak korelasi log.")]
    return [skipped("ntp_sync", C.SYSTEM, "Status NTP tidak dapat dibaca")]


def eval_reboot(out: str) -> list[CheckResult]:
    if out.strip() == "yes":
        return [issue("reboot_required", C.SYSTEM, "Server menunggu reboot (update kernel/library)", S.LOW,
                      recommendation="Jadwalkan reboot agar update keamanan aktif.")]
    return [passed("reboot_required", C.SYSTEM, "Tidak ada reboot tertunda")]


def _sshd_value(text: str, key: str, from_files: bool) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if from_files and line.lower().startswith("match "):
            break  # values inside Match blocks are conditional; stop at the first one
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower() and not line.startswith("#"):
            return parts[1].strip().lower()  # sshd uses the first value it reads
    return None


def eval_sshd(out: str) -> list[CheckResult]:
    from_files = out.startswith("__FILES__")
    confidence = 0.8 if from_files else 1.0
    root = _sshd_value(out, "PermitRootLogin", from_files) or ("prohibit-password" if not from_files else None)
    pw = _sshd_value(out, "PasswordAuthentication", from_files) or "yes"
    ev = {"PermitRootLogin": root, "PasswordAuthentication": pw,
          "source": "config files (sshd -T tidak tersedia)" if from_files else "sshd -T"}
    results = []
    if root == "yes":
        results.append(issue("ssh_root_login", C.CONFIGURATION, "SSH mengizinkan login root dengan password", S.MEDIUM,
                             evidence=ev, confidence=confidence,
                             recommendation="Set `PermitRootLogin prohibit-password` atau `no`, lalu reload sshd."))
    else:
        results.append(passed("ssh_root_login", C.CONFIGURATION, "Login root via password dinonaktifkan", evidence=ev))
    if pw == "yes":
        results.append(issue("ssh_password_auth", C.CONFIGURATION, "SSH menerima autentikasi password", S.LOW,
                             evidence=ev, confidence=confidence,
                             recommendation="Gunakan SSH key dan set `PasswordAuthentication no` (pastikan key sudah terpasang)."))
    else:
        results.append(passed("ssh_password_auth", C.CONFIGURATION, "Autentikasi password SSH dinonaktifkan", evidence=ev))
    return results


def eval_processes(out: str) -> list[CheckResult]:
    procs = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5:
            procs.append({"pid": parts[0], "user": parts[1], "cpu": parts[2], "mem": parts[3], "args": parts[4][:300]})
    top = procs[:5]
    results: list[CheckResult] = []
    for p in procs:
        exe = p["args"].split()[0] if p["args"] else ""
        if MINER_NAMES.search(p["args"]):
            results.append(issue(
                "suspicious_process", C.MALWARE, f"Proses crypto-miner terdeteksi (PID {p['pid']})", S.CRITICAL,
                target=exe[:1024], evidence={"process": p}, confidence=0.9,
                description="Nama proses cocok dengan crypto-miner yang umum dipakai pada server yang disusupi.",
                recommendation="Isolasi server, simpan bukti (ps, /proc/<pid>/exe, crontab), cari persistence, "
                               "lalu rotasi credential. Jangan langsung kill sebelum bukti disimpan."))
        elif exe.startswith(SUSPICIOUS_EXEC_DIRS):
            results.append(issue(
                "suspicious_process", C.MALWARE, f"Proses berjalan dari direktori sementara ({exe})"[:255], S.HIGH,
                target=exe[:1024], evidence={"process": p}, confidence=0.7,
                description="Binary yang dijalankan dari /tmp, /dev/shm atau /var/tmp sering merupakan malware.",
                recommendation="Periksa asal file, hash, dan parent process; simpan bukti sebelum tindakan apa pun."))
    if not results:
        results.append(passed("suspicious_process", C.MALWARE, "Tidak ada proses mencurigakan", evidence={"top_cpu": top}))
    return results


# --- runner ---------------------------------------------------------------

CHECKS: list[tuple[str, C, str, Callable[[str], list[CheckResult]]]] = [
    ("cpu_load", C.SYSTEM, CMD_LOAD, eval_load),
    ("memory", C.SYSTEM, CMD_MEMINFO, eval_memory),
    ("disk_usage", C.STORAGE, CMD_DISK, lambda o: eval_df(o, inode=False)),
    ("inode_usage", C.STORAGE, CMD_INODE, lambda o: eval_df(o, inode=True)),
    ("failed_services", C.SERVICE, CMD_FAILED_UNITS, eval_failed_units),
    ("exposed_db_ports", C.NETWORK, CMD_LISTEN, eval_listen),
    ("ntp_sync", C.SYSTEM, CMD_NTP, eval_ntp),
    ("reboot_required", C.SYSTEM, CMD_REBOOT, eval_reboot),
    ("ssh_config", C.CONFIGURATION, CMD_SSHD, eval_sshd),
    ("suspicious_process", C.MALWARE, CMD_PS, eval_processes),
]


async def timed(check: str, category: C, fn: Callable[[], Awaitable[list[CheckResult]]]) -> list[CheckResult]:
    start = time.monotonic()
    try:
        results = await fn()
    except Exception as exc:  # one broken check must not abort the whole assessment
        results = [error(check, category, f"{type(exc).__name__}: {exc}"[:200])]
    ms = int((time.monotonic() - start) * 1000)
    for r in results:
        r.duration_ms = ms
    return results


async def run_server_checks(runner: Runner) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check, category, command, evaluate in CHECKS:
        async def one(command=command, evaluate=evaluate):
            out = await runner.run(command)
            return evaluate(out.stdout)
        results += await timed(check, category, one)
    return results


def unreachable(message: str) -> CheckResult:
    return issue("ssh_connectivity", C.CONNECTIVITY, "Server tidak dapat dijangkau via SSH", S.HIGH,
                 value=clip(message, 255), evidence={"error": clip(message)},
                 recommendation="Periksa jaringan/firewall, status sshd, dan credential server.")
