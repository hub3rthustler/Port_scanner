### scanner.py
# Multi-threaded scanning logic with banner grabbing

import socket
import threading
import queue
import ssl


class PortScanner:
    def __init__(self, target, ports, max_threads=100, progress_callback=None, stop_event=None):
        """
        :param target:            IP address or hostname to scan
        :param ports:             list of port numbers to scan
        :param max_threads:       maximum worker threads (default 100)
        :param progress_callback: optional callable(scanned, total) called after each port attempt
        :param stop_event:        optional threading.Event; scanning stops when it is set
        """
        self.target = target
        self.ports = ports
        self.open_ports = {}
        self.q = queue.Queue()
        self.max_threads = max_threads
        self.progress_callback = progress_callback
        self.stop_event = stop_event or threading.Event()
        self._lock = threading.Lock()
        self._scanned_count = 0

        # Banner grabbing probes for common services
        self.probes = {
            21: b'',  # FTP - sends banner on connect
            22: b'',  # SSH - sends banner on connect
            23: b'',  # Telnet - sends banner on connect
            25: b'',  # SMTP - sends banner on connect
            53: b'',  # DNS - UDP, but for TCP
            80: b'GET / HTTP/1.0\r\n\r\n',  # HTTP
            110: b'',  # POP3 - sends banner
            143: b'',  # IMAP - sends banner
            443: b'GET / HTTP/1.0\r\n\r\n',  # HTTPS
            993: b'',  # IMAPS
            995: b'',  # POP3S
            3306: b'',  # MySQL - might send version
            5432: b'',  # PostgreSQL
        }

    def _get_banner(self, sock, port):
        """Get service banner by sending appropriate probe"""
        probe = self.probes.get(port, b'')
        if port == 443:
            # Handle SSL for HTTPS
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    ssock.send(probe)
                    ssock.settimeout(1)
                    banner = ssock.recv(1024).decode(errors='replace').strip()
                    return banner if banner else "No banner"
            except Exception:
                return "No banner"
        elif probe:
            try:
                sock.send(probe)
                sock.settimeout(1)  # Shorter timeout for response
                banner = sock.recv(1024).decode(errors='replace').strip()
                return banner if banner else "No banner"
            except Exception:
                return "No banner"
        else:
            # For unknown ports, try to receive unsolicited banner
            try:
                sock.settimeout(0.5)  # Very short timeout
                banner = sock.recv(1024).decode(errors='replace').strip()
                return banner if banner else "No banner"
            except Exception:
                return "No banner"

    def _port_scan_worker(self):
        while not self.q.empty():
            if self.stop_event.is_set():
                # Drain the queue so q.join() can finish
                try:
                    while True:
                        self.q.get_nowait()
                        self.q.task_done()
                except queue.Empty:
                    pass
                return

            try:
                port = self.q.get_nowait()
            except queue.Empty:
                return

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        banner = self._get_banner(s, port)

                        with self._lock:
                            self.open_ports[port] = banner
            except Exception:
                pass
            finally:
                with self._lock:
                    self._scanned_count += 1
                    scanned = self._scanned_count

                if self.progress_callback:
                    self.progress_callback(scanned, len(self.ports))

                self.q.task_done()

    def scan(self):
        for port in self.ports:
            self.q.put(port)

        thread_count = min(self.max_threads, len(self.ports))
        threads = [threading.Thread(target=self._port_scan_worker, daemon=True)
                   for _ in range(thread_count)]

        for t in threads:
            t.start()

        self.q.join()

        return dict(sorted(self.open_ports.items()))

    def scan_with_banner(self):
        return self.scan()