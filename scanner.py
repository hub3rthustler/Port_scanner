"""Concurrent TCP port scanning with lightweight banner grabbing."""

from __future__ import annotations

import queue
import socket
import ssl
import threading
from collections.abc import Callable, Iterable
from typing import Any


ProgressCallback = Callable[[int, int], None]
ResolvedAddress = tuple[int, int, int, tuple[Any, ...]]


class PortScanner:
    """Scan TCP ports for one host.

    Hostname resolution happens once per scan. Instances may be reused after a
    completed scan, provided their stop event has been cleared by the caller.
    """

    TLS_PORTS = frozenset({443, 465, 993, 995})
    PROBES = {
        21: b"",
        22: b"",
        23: b"",
        25: b"",
        53: b"",
        80: b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
        110: b"",
        143: b"",
        443: b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
        465: b"",
        993: b"",
        995: b"",
        3306: b"",
        5432: b"",
    }

    def __init__(
        self,
        target: str,
        ports: Iterable[int],
        max_threads: int = 100,
        progress_callback: ProgressCallback | None = None,
        stop_event: threading.Event | None = None,
        connect_timeout: float = 2.0,
        banner_timeout: float = 1.0,
    ) -> None:
        self.target = target.strip()
        port_list = list(ports)
        if not port_list or any(
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
            for port in port_list
        ):
            raise ValueError("Ports must contain integer values from 1 to 65535")
        self.ports = sorted(set(port_list))
        self.max_threads = max_threads
        self.progress_callback = progress_callback
        self.stop_event = stop_event or threading.Event()
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout

        if not self.target:
            raise ValueError("Target cannot be empty")
        if (
            not isinstance(max_threads, int)
            or isinstance(max_threads, bool)
            or max_threads < 1
        ):
            raise ValueError("max_threads must be a positive integer")
        if (
            not isinstance(connect_timeout, (int, float))
            or not isinstance(banner_timeout, (int, float))
            or connect_timeout <= 0
            or banner_timeout <= 0
        ):
            raise ValueError("Timeouts must be positive")

        self.open_ports: dict[int, str] = {}
        self.callback_error: Exception | None = None
        self._queue: queue.Queue[int] = queue.Queue()
        self._state_lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._scanned_count = 0
        self._addresses: list[ResolvedAddress] = []

    def _resolve_target(self) -> list[ResolvedAddress]:
        """Resolve IPv4 and IPv6 addresses once and remove duplicates."""
        infos = socket.getaddrinfo(
            self.target,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        addresses: list[ResolvedAddress] = []
        seen: set[tuple[Any, ...]] = set()
        for family, socktype, proto, _canonical_name, sockaddr in infos:
            key = (family, socktype, proto, sockaddr)
            if key not in seen:
                seen.add(key)
                addresses.append((family, socktype, proto, sockaddr))
        if not addresses:
            raise OSError(f"No address found for {self.target}")
        return addresses

    @staticmethod
    def _with_port(sockaddr: tuple[Any, ...], port: int) -> tuple[Any, ...]:
        return (sockaddr[0], port, *sockaddr[2:])

    def _probe_for_port(self, port: int) -> bytes:
        probe = self.PROBES.get(port, b"")
        if port in {80, 443}:
            ascii_target = self.target.encode("idna").decode("ascii")
            return (
                f"GET / HTTP/1.0\r\nHost: {ascii_target}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        return probe

    def _read_banner(self, sock: socket.socket, probe: bytes) -> str:
        sock.settimeout(self.banner_timeout)
        if probe:
            sock.sendall(probe)
        banner = sock.recv(1024).decode(errors="replace").strip()
        return banner or "No banner"

    def _get_banner(self, sock: socket.socket, port: int) -> str:
        """Read a small service banner, using TLS for implicit TLS ports."""
        probe = self._probe_for_port(port)
        try:
            if port in self.TLS_PORTS:
                context = ssl.create_default_context()
                # This is service discovery, not server identity verification.
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=self.target) as tls_sock:
                    return self._read_banner(tls_sock, probe)
            return self._read_banner(sock, probe)
        except (OSError, ssl.SSLError):
            return "No banner"

    def _register_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._active_sockets.add(sock)

    def _unregister_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._active_sockets.discard(sock)

    def _scan_port(self, port: int) -> None:
        for family, socktype, proto, sockaddr in self._addresses:
            if self.stop_event.is_set():
                return

            sock = socket.socket(family, socktype, proto)
            self._register_socket(sock)
            try:
                sock.settimeout(self.connect_timeout)
                if sock.connect_ex(self._with_port(sockaddr, port)) == 0:
                    banner = self._get_banner(sock, port)
                    if not self.stop_event.is_set():
                        with self._state_lock:
                            self.open_ports[port] = banner
                    return
            except OSError:
                continue
            finally:
                self._unregister_socket(sock)
                sock.close()

    def _report_progress(self) -> None:
        with self._state_lock:
            self._scanned_count += 1
            scanned = self._scanned_count

        if self.progress_callback:
            try:
                self.progress_callback(scanned, len(self.ports))
            except Exception as exc:  # A UI callback must never kill a worker.
                self.callback_error = exc

    def _port_scan_worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                port = self._queue.get_nowait()
            except queue.Empty:
                return

            try:
                self._scan_port(port)
            finally:
                self._report_progress()
                self._queue.task_done()

    def cancel(self) -> None:
        """Request cancellation and interrupt sockets that are currently active."""
        self.stop_event.set()
        with self._state_lock:
            active_sockets = tuple(self._active_sockets)
        for sock in active_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def scan(self) -> dict[int, str]:
        """Run the scan and return a port-to-banner mapping."""
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("This scanner is already running")

        try:
            self.open_ports = {}
            self.callback_error = None
            self._scanned_count = 0
            self._queue = queue.Queue()

            if self.stop_event.is_set():
                return {}

            self._addresses = self._resolve_target()
            for port in self.ports:
                self._queue.put(port)

            thread_count = min(self.max_threads, len(self.ports))
            threads = [
                threading.Thread(target=self._port_scan_worker, daemon=True)
                for _ in range(thread_count)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            return dict(sorted(self.open_ports.items()))
        finally:
            self._scan_lock.release()

    def scan_with_banner(self) -> dict[int, str]:
        """Backward-compatible alias for :meth:`scan`."""
        return self.scan()
