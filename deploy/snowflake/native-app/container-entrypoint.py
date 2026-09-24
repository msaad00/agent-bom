"""Prepare one Native App block mount, then permanently drop API privileges."""

import os
import secrets
import stat
import sys

STATE = "/var/lib/agent-bom"
UID = GID = 10001


def prepare_state() -> None:
    if os.getuid() != 0 or not os.path.ismount(STATE):
        raise RuntimeError("Native App requires its dedicated mounted evidence directory")
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Never walk the volume or follow links while privileged.
        os.fchown(fd, UID, GID)
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)
    if os.getuid() != UID or os.getgid() != GID or os.getgroups():
        raise RuntimeError("Native App could not drop process privileges")
    os.umask(0o077)
    # Store the signing key with the evidence so restart does not invalidate the
    # audit chain. A volume backup contains both and needs equivalent protection.
    key_path = STATE + "/audit-hmac.key"
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != UID or info.st_nlink != 1 or info.st_mode & 0o077:
                raise RuntimeError("Native App audit key permissions are invalid")
            value = os.read(fd, 129)
            if len(value) != 64 or any(c not in b"0123456789abcdef" for c in value):
                raise RuntimeError("Native App audit key is invalid")
        finally:
            os.close(fd)
    else:
        with os.fdopen(fd, "wb") as key:
            key.write(secrets.token_hex(32).encode("ascii"))
            key.flush()
            os.fsync(key.fileno())
    # An exclusive probe verifies write access after privilege reduction.
    probe = STATE + "/.write-probe-" + secrets.token_hex(16)
    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    os.unlink(probe)
    for name, value in {
        "AGENT_BOM_DB": STATE + "/control-plane.db",
        "AGENT_BOM_GRAPH_DB": STATE + "/control-plane.db",
        "AGENT_BOM_STATE_DIR": STATE,
        "AGENT_BOM_AUDIT_HMAC_KEY_FILE": key_path,
        "AGENT_BOM_REQUIRE_AUDIT_HMAC": "1",
        "AGENT_BOM_CONTROL_PLANE_REPLICAS": "1",
    }.items():
        if os.environ.get(name, value) != value:
            raise RuntimeError("Native App persistence configuration does not match its volume")
        os.environ[name] = value


def main() -> None:
    try:
        prepare_state()
    except (OSError, RuntimeError):
        # No exception detail: mount paths and environment may contain secrets.
        sys.stderr.write("Native App durable state initialization failed; API was not started\n")
        raise SystemExit(1) from None
    os.execv("/app/.venv/bin/agent-bom", ["agent-bom", "api", "--host", "0.0.0.0", "--port", "8422"])


if __name__ == "__main__":
    main()
