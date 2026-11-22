#!/usr/bin/env python3

import argparse
import errno
import ipaddress
import socket
import sys
import time
from datetime import datetime

# ----------------------------- Configuration ------------------------------ #
MIN_PORT, MAX_PORT = 1, 65535
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

LOCAL_TARGETS = {"localhost", "127.0.0.1", "::1"}
REMOTE_TARGETS = {"scanme.nmap.org"}   # explicitly permitted test host

# ".invalid" is a reserved TLD (RFC 2606) that can never resolve. It is allowed
# ONLY so the "unreachable host" error handling can be demonstrated safely: it
# fails at the DNS step and no packets are ever sent to anyone.
SAFE_TEST_SUFFIX = ".invalid"

# Politeness limits for non-local targets (ethical scanning guidelines)
REMOTE_MIN_DELAY = 0.2      # seconds between connection attempts
REMOTE_MAX_PORTS = 100      # never scan more than this many ports remotely

DEFAULT_TIMEOUT = 1.0       # seconds to wait for each connection attempt
DEFAULT_DELAY = 0.05        # seconds to pause between attempts

# Errors that mean the whole host/network can't be reached (not just one port)
UNREACHABLE_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}

# Port states
OPEN, CLOSED, FILTERED, ERROR = "OPEN", "CLOSED", "FILTERED", "ERROR"


# ------------------------------ Custom errors ------------------------------ #
class ScannerError(Exception):
    """Base class for errors we want to show the user as a friendly message."""


class UnauthorizedTargetError(ScannerError):
    """Raised when the target is not on the approved list."""


class InvalidPortError(ScannerError):
    """Raised when a port or port range is malformed or out of range."""


class HostUnreachableError(ScannerError):
    """Raised when the target host cannot be resolved or reached."""


# ------------------------------- Validation -------------------------------- #
def validate_target(host: str) -> str:
    """Return the normalized host if it is authorized; otherwise raise."""
    host = host.strip().lower()
    if host in LOCAL_TARGETS or host in REMOTE_TARGETS or host.endswith(SAFE_TEST_SUFFIX):
        return host
    raise UnauthorizedTargetError(
        f"'{host}' is NOT an authorized target. "
        f"Only localhost/127.0.0.1 and scanme.nmap.org may be scanned."
    )


def parse_ports(spec: str) -> list[int]:
    """
    Turn a string like '22,80,100-110' into a sorted list of unique ports.
    Raises InvalidPortError for anything malformed or outside 1-65535.
    """
    if not spec or not spec.strip():
        raise InvalidPortError("No ports specified.")

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise InvalidPortError(f"Empty entry in port list: '{spec}'")
        try:
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
            else:
                start = end = int(part)
        except ValueError:
            raise InvalidPortError(f"'{part}' is not a valid port or range.") from None

        for value in (start, end):
            if not MIN_PORT <= value <= MAX_PORT:
                raise InvalidPortError(
                    f"Port {value} is out of range ({MIN_PORT}-{MAX_PORT})."
                )
        if start > end:
            raise InvalidPortError(f"Invalid range '{part}': start is greater than end.")
        ports.update(range(start, end + 1))

    return sorted(ports)


def resolve_host(host: str) -> tuple[int, str]:
    """Resolve a hostname to (address_family, ip). Raises HostUnreachableError."""
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise HostUnreachableError(f"Could not resolve '{host}': {err}") from None

    family, _, _, _, sockaddr = info[0]
    ip = sockaddr[0]

    # Safety check: anything claiming to be "local" must really be loopback
    if host in LOCAL_TARGETS and not ipaddress.ip_address(ip).is_loopback:
        raise UnauthorizedTargetError(f"'{host}' resolved to non-loopback address {ip}.")
    return family, ip


# -------------------------------- Scanning --------------------------------- #
def service_name(port: int) -> str:
    """Look up the well-known service name for a port (or '-' if unknown)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def scan_port(family: int, ip: str, port: int, timeout: float) -> tuple[str, str]:
    """
    Try one TCP connection and return (state, detail).
    Raises HostUnreachableError if the network/host itself is unreachable.
    """
    # 'with' guarantees the socket is closed even if an exception occurs
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return OPEN, "connection accepted"
        except ConnectionRefusedError:
            return CLOSED, "connection refused"
        except socket.timeout:
            return FILTERED, "no response (timed out)"
        except OSError as err:
            if err.errno in UNREACHABLE_ERRNOS:
                raise HostUnreachableError(f"Host/network unreachable: {err}") from None
            return ERROR, str(err)


def run_scan(host: str, ports: list[int], timeout: float, delay: float,
             show_closed: bool) -> dict:
    """Scan every port in order, printing results as we go. Returns a summary."""
    family, ip = resolve_host(host)
    is_remote = host in REMOTE_TARGETS

    # Enforce polite behaviour toward remote hosts
    if is_remote:
        if len(ports) > REMOTE_MAX_PORTS:
            raise InvalidPortError(
                f"Too many ports for a remote host ({len(ports)}). "
                f"Limit is {REMOTE_MAX_PORTS}."
            )
        delay = max(delay, REMOTE_MIN_DELAY)

    print("=" * 62)
    print(f" Port scan started : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f" Target            : {host} ({ip})")
    print(f" Ports             : {len(ports)} "
          f"({ports[0]}-{ports[-1]})" if len(ports) > 1 else f" Ports             : {ports[0]}")
    print(f" Timeout / delay   : {timeout}s / {delay}s")
    print("=" * 62)
    print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<14}DETAIL")

    counts = {OPEN: 0, CLOSED: 0, FILTERED: 0, ERROR: 0}
    start = time.perf_counter()

    for index, port in enumerate(ports):
        state, detail = scan_port(family, ip, port, timeout)
        counts[state] += 1

        # Always show non-closed ports; show closed ones only if requested
        if state != CLOSED or show_closed:
            print(f"{port:<8}{state:<10}{service_name(port):<14}{detail}")

        if index < len(ports) - 1:
            time.sleep(delay)   # be polite: pause between attempts

    elapsed = time.perf_counter() - start
    counts["elapsed"] = elapsed
    return counts


def print_summary(host: str, ports: list[int], counts: dict) -> None:
    """Print the closing summary block."""
    print("-" * 62)
    print(f" Scan finished     : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f" Target            : {host}")
    print(f" Ports scanned     : {len(ports)}")
    print(f" Open: {counts[OPEN]}  Closed: {counts[CLOSED]}  "
          f"Filtered: {counts[FILTERED]}  Errors: {counts[ERROR]}")
    print(f" Elapsed time      : {counts['elapsed']:.2f} seconds")
    print("=" * 62)


# ----------------------------------- CLI ----------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Educational TCP port scanner (localhost and scanme.nmap.org only).")
    parser.add_argument("host", help="target: localhost, 127.0.0.1, or scanme.nmap.org")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", help="ports, e.g. '22,80,443' or '1-100' or '22,80,100-110'")
    group.add_argument("--common", action="store_true",
                       help=f"scan common ports: {COMMON_PORTS}")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"seconds to wait per port (default {DEFAULT_TIMEOUT})")
    parser.add_argument("-d", "--delay", type=float, default=DEFAULT_DELAY,
                        help=f"seconds between attempts (default {DEFAULT_DELAY}; "
                             f"minimum {REMOTE_MIN_DELAY} for remote hosts)")
    parser.add_argument("--show-closed", action="store_true",
                        help="also list closed ports (hidden by default)")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        if args.timeout <= 0 or args.delay < 0:
            raise InvalidPortError("Timeout must be > 0 and delay must be >= 0.")
        host = validate_target(args.host)

        if args.common:
            ports = COMMON_PORTS
        elif args.ports:
            ports = parse_ports(args.ports)
        else:
            raise InvalidPortError("Specify ports with -p (e.g. -p 1-100) or use --common.")

        # Small scans show closed ports automatically so results are easy to read
        show_closed = args.show_closed or len(ports) <= 25
        counts = run_scan(host, ports, args.timeout, args.delay, show_closed)
        print_summary(host, ports, counts)
        return 0

    except ScannerError as err:
        print(f"[ERROR] {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
