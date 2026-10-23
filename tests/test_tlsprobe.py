from contextlib import contextmanager
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

from snellctl.deployment import NodeSpec
from snellctl.hostprep import PreparationError
from snellctl.tlsprobe import LocalTLSProbe


class TLSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.cert = root / "certificate.pem"
        cls.key = root / "private.pem"
        # Disposable test-only CA/leaf, never used for the actual node or ACME.
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "1",
            "-config", str(Path(__file__).parent / "fixtures/tls-test.cnf"),
            "-keyout", str(cls.key), "-out", str(cls.cert),
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        cls.key.chmod(0o600)

    @contextmanager
    def server(self, *, reject=True, status=404):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert), str(self.key))
        names = []
        def callback(connection, name, original):
            names.append(name)
            if reject and name != "node.example.net":
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        context.sni_callback = callback
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            listener.settimeout(0.1)
        except BaseException:
            listener.close()
            raise
        port = listener.getsockname()[1]
        stopping = threading.Event()
        errors = []
        def serve():
            while not stopping.is_set():
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    with raw:
                        raw.settimeout(2)
                        with context.wrap_socket(raw, server_side=True) as tls:
                            request = tls.recv(4096)
                            if request:
                                tls.sendall(f"HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
                except (ssl.SSLError, ConnectionError, TimeoutError):
                    pass
                except Exception as error:
                    errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield port, names
        finally:
            stopping.set()
            listener.close()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_real_tls13_chain_hostname_certificate_and_four_rejections(self):
        with self.server() as (port, names):
            spec = NodeSpec("node.example.net", tls_port=port)
            self.assertTrue(LocalTLSProbe(cafile=str(self.cert))(spec, port, self.cert.read_bytes()))
        self.assertEqual(names, ["node.example.net", "wrong-sni.invalid", None, "wrong-sni.invalid", None])

    def test_handshake_success_with_bad_sni_does_not_pass(self):
        with self.server(reject=False) as (port, _):
            spec = NodeSpec("node.example.net", tls_port=port)
            with self.assertRaisesRegex(PreparationError, "仍可完成握手"):
                LocalTLSProbe(cafile=str(self.cert))(spec, port, self.cert.read_bytes())

    def test_wrong_http_status_is_failure(self):
        with self.server(status=200) as (port, _):
            spec = NodeSpec("node.example.net", tls_port=port)
            with self.assertRaisesRegex(PreparationError, "返回状态"):
                LocalTLSProbe(cafile=str(self.cert))(spec, port, self.cert.read_bytes())

    def test_disk_runtime_mismatch_is_failure(self):
        with self.server() as (port, _):
            spec = NodeSpec("node.example.net", tls_port=port)
            different = ssl.DER_cert_to_PEM_cert(b"different certificate").encode()
            with self.assertRaisesRegex(PreparationError, "不一致"):
                LocalTLSProbe(cafile=str(self.cert))(spec, port, different)

    def test_untrusted_cert_is_failure(self):
        with self.server() as (port, _):
            spec = NodeSpec("node.example.net", tls_port=port)
            with self.assertRaises(PreparationError):
                LocalTLSProbe(cafile=None)(spec, port, self.cert.read_bytes())

    def test_missing_sni_must_really_be_rejected(self):
        with self.server(reject=False) as (port, _):
            with self.assertRaisesRegex(PreparationError, "仍可完成握手"):
                LocalTLSProbe(cafile=str(self.cert))._rejected(port, ssl.TLSVersion.TLSv1_3, None)

    def test_refused_connection_is_not_sni_rejection(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with self.assertRaises(OSError):
            LocalTLSProbe()._rejected(port, ssl.TLSVersion.TLSv1_3, None)

    def test_arbitrary_port_rejected_before_connect(self):
        with self.assertRaises(PreparationError):
            LocalTLSProbe()(NodeSpec("node.example.net"), 65000, b"")


if __name__ == "__main__":
    unittest.main()
