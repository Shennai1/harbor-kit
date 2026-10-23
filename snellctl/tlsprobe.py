"""Bounded loopback-only TLS checks. Never resolve the public domain or use a proxy."""

import http.client
import socket
import ssl

from .deployment import NodeSpec
from .hostprep import PreparationError


class LocalTLSProbe:
    def __init__(self, *, cafile="/etc/ssl/certs/ca-certificates.crt", timeout=5):
        self.cafile = cafile
        self.timeout = timeout

    def __call__(self, spec: NodeSpec, port: int, certificate: bytes):
        if port not in {spec.tls_port, spec.public_port}:
            raise PreparationError("TLS 检查端口不在本次配置中。")
        try:
            expected = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
            context = ssl.create_default_context(cafile=self.cafile)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["http/1.1"])
            with socket.create_connection(("127.0.0.1", port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=spec.domain) as connection:
                    if connection.version() != "TLSv1.3" or connection.getpeercert(binary_form=True) != expected:
                        raise PreparationError("运行证书与磁盘证书不一致，或 TLS 版本不符。")
                    connection.sendall(("GET / HTTP/1.1\r\nHost: " + spec.domain + "\r\nConnection: close\r\n\r\n").encode("ascii"))
                    with http.client.HTTPResponse(connection) as response:
                        response.begin()
                        if response.status != 404:
                            raise PreparationError("本机 HTTPS 返回状态不符合预期。")
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                for hostname in ("wrong-sni.invalid", None):
                    self._rejected(port, version, hostname)
        except PreparationError:
            raise
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            raise PreparationError("本机 TLS/HTTPS 检查失败；未显示原始网络或证书内容。") from None
        return True

    def _rejected(self, port, version, hostname):
        # Disable certificate checks only here: rejection must come from the server.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = version
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=hostname):
                    pass
        except ssl.SSLError as error:
            if error.reason == "TLSV1_UNRECOGNIZED_NAME":
                return
            raise PreparationError("错误或缺失 SNI 未返回明确的拒绝握手警报。") from None
        raise PreparationError("错误或缺失 SNI 仍可完成握手。")
