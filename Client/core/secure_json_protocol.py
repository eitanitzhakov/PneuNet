import json
from typing import Any, Dict, Optional
import base64


class SecureJsonProtocol:
    def __init__(self, inner_protocol, cipher):
        self.inner = inner_protocol
        self.cipher = cipher

    def send(self, sock, obj: Dict[str, Any]) -> None:
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ct = self.cipher.aes_encrypt(plain)
        b64 = base64.b64encode(ct).decode("ascii")
        self.inner.send(sock, {"type": "ENC", "payload": b64})

    def recv(self, sock) -> Optional[Dict[str, Any]]:
        wrapper = self.inner.recv(sock)  # here the real rcv from the socket!
        if wrapper is None:
            return None

        if str(wrapper.get("type", "")).upper() != "ENC":
            raise ValueError("non encrypted message received after handshake")

        b64 = wrapper.get("payload", "")
        ct = base64.b64decode(b64.encode("ascii"))
        plain_str = self.cipher.aes_decrypt(ct)
        return json.loads(plain_str)
