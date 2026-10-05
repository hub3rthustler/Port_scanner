import socket
import threading
import unittest
from unittest import mock

from scanner import PortScanner


class PortScannerTests(unittest.TestCase):
    def test_rejects_invalid_configuration(self):
        with self.assertRaises(ValueError):
            PortScanner("localhost", [0])
        with self.assertRaises(ValueError):
            PortScanner("localhost", [80], max_threads=0)
        with self.assertRaises(ValueError):
            PortScanner("localhost", [80], connect_timeout=0)

    def test_callback_exception_does_not_block_scan(self):
        def failing_callback(_scanned, _total):
            raise RuntimeError("callback failed")

        scanner = PortScanner(
            "localhost",
            [80, 81],
            max_threads=1,
            progress_callback=failing_callback,
        )
        fake_address = [(socket.AF_INET, socket.SOCK_STREAM, 0, ("127.0.0.1", 0))]
        with (
            mock.patch.object(scanner, "_resolve_target", return_value=fake_address),
            mock.patch.object(scanner, "_scan_port"),
        ):
            self.assertEqual(scanner.scan(), {})

        self.assertIsInstance(scanner.callback_error, RuntimeError)
        self.assertEqual(scanner._scanned_count, 2)

    def test_reads_banner_from_local_tcp_service(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_banner():
            connection, _address = listener.accept()
            with connection:
                connection.sendall(b"TestService 1.0\r\n")
            listener.close()

        server_thread = threading.Thread(target=serve_banner, daemon=True)
        server_thread.start()

        scanner = PortScanner(
            "127.0.0.1",
            [port],
            max_threads=1,
            connect_timeout=1,
            banner_timeout=1,
        )
        self.assertEqual(scanner.scan(), {port: "TestService 1.0"})
        server_thread.join(timeout=1)
        self.assertFalse(server_thread.is_alive())

    def test_cancel_sets_stop_event(self):
        scanner = PortScanner("localhost", [80])
        scanner.cancel()
        self.assertTrue(scanner.stop_event.is_set())
        self.assertEqual(scanner.scan(), {})

    def test_cancel_interrupts_active_banner_read(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted = threading.Event()

        def hold_connection():
            connection, _address = listener.accept()
            accepted.set()
            with connection:
                connection.recv(1)
            listener.close()

        server_thread = threading.Thread(target=hold_connection, daemon=True)
        server_thread.start()
        scanner = PortScanner(
            "127.0.0.1",
            [port],
            max_threads=1,
            connect_timeout=1,
            banner_timeout=5,
        )
        scan_thread = threading.Thread(target=scanner.scan, daemon=True)
        scan_thread.start()

        self.assertTrue(accepted.wait(timeout=1))
        scanner.cancel()
        scan_thread.join(timeout=1)
        server_thread.join(timeout=1)

        self.assertFalse(scan_thread.is_alive())
        self.assertFalse(server_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
