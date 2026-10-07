import asyncio

from app.assessment import server_checks as sc
from app.core.enums import CheckStatus, Severity
from tests.fakes import FakeRunner

DF = """Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         41152736  38000000   3152736      93% /
/dev/sdb1        103081248  84000000  19081248      82% /var/www
/dev/sdc1        103081248  10000000  93081248      10% /backup
"""
MEMINFO = "MemTotal:  8000000 kB\nMemFree: 100000 kB\nMemAvailable:  600000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
SS = """tcp   LISTEN 0 511   0.0.0.0:80    0.0.0.0:*
tcp   LISTEN 0 80    0.0.0.0:3306  0.0.0.0:*
tcp   LISTEN 0 511   127.0.0.1:6379 0.0.0.0:*
tcp   LISTEN 0 128   [::]:22       [::]:*
"""
PS = """  4242 www-data 398.0 12.1 /tmp/.x/xmrig -o pool.example:3333
  5151 www-data  5.0  1.0 /dev/shm/.cache/kworker
  1 root 0.1 0.1 /sbin/init
"""


def by_check(results, name):
    return [r for r in results if r.check == name]


def test_disk_thresholds_per_mount():
    res = sc.eval_df(DF, inode=False)
    sev = {r.target: (r.status, r.severity) for r in res}
    assert sev["/"] == (CheckStatus.FAIL, Severity.HIGH)
    assert sev["/var/www"] == (CheckStatus.WARNING, Severity.MEDIUM)
    assert sev["/backup"][0] == CheckStatus.PASS


def test_df_ignores_bind_mounts_and_duplicate_devices():
    out = """Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/sda1 100 95 5 95% /etc/hosts
/dev/sda1 100 95 5 95% /
/dev/sda1 100 95 5 95% /var/lib/docker
tmpfs 100 1 99 1% /run/user/0
"""
    res = sc.eval_df(out, inode=False)
    assert [r.target for r in res] == ["/"]


def test_memory_low():
    [r] = sc.eval_memory(MEMINFO)  # 7.5% available
    assert r.severity == Severity.MEDIUM and r.is_issue


def test_load_ratio():
    assert not sc.eval_load("0.5 1.0 1.0 2/300 999\n4\n86400.0 1.0\n")[0].is_issue
    assert sc.eval_load("9 9.0 9 2/300 999\n4\n86400.0 1.0\n")[0].severity == Severity.MEDIUM


def test_exposed_db_port_only_when_public():
    [r] = sc.eval_listen(SS)
    assert r.is_issue and "MySQL" in r.value and "Redis" not in r.value


def test_failed_units_and_no_systemd():
    [r] = sc.eval_failed_units("nginx.service loaded failed failed A high performance web server\n")
    assert r.is_issue and r.value == "nginx.service"
    assert sc.eval_failed_units("__NO_SYSTEMD__")[0].status == CheckStatus.SKIPPED


def test_sshd_from_sshd_t_and_from_files():
    res = sc.eval_sshd("permitrootlogin yes\npasswordauthentication no\n")
    assert by_check(res, "ssh_root_login")[0].is_issue
    assert not by_check(res, "ssh_password_auth")[0].is_issue
    # File fallback: first value wins, Match blocks ignored, lower confidence.
    files = "__FILES__\nPasswordAuthentication no\n#PermitRootLogin yes\nMatch User x\nPermitRootLogin yes\n"
    res = sc.eval_sshd(files)
    assert not by_check(res, "ssh_root_login")[0].is_issue
    assert not by_check(res, "ssh_password_auth")[0].is_issue


def test_suspicious_processes():
    res = sc.eval_processes(PS)
    miner = [r for r in res if r.severity == Severity.CRITICAL]
    tmp = [r for r in res if r.severity == Severity.HIGH]
    assert len(miner) == 1 and miner[0].target == "/tmp/.x/xmrig"
    assert len(tmp) == 1 and tmp[0].target == "/dev/shm/.cache/kworker"


def test_run_server_checks_uses_only_fixed_commands_and_survives_bad_output():
    runner = FakeRunner({r"loadavg": "garbage", r"meminfo": MEMINFO, r"df -P -i": DF, r"df -P": DF,
                         r"systemctl": "", r"ss -H": SS, r"timedatectl": "yes", r"reboot-required": "no",
                         r"sshd": "permitrootlogin no\npasswordauthentication no\n", r"ps -eo": PS})
    results = asyncio.run(sc.run_server_checks(runner))
    # A parser crash becomes an ERROR result instead of aborting the assessment.
    assert by_check(results, "cpu_load")[0].status == CheckStatus.ERROR
    assert {c for c, _ in runner.calls} == {cmd for _, _, cmd, _ in sc.CHECKS}
