import socket
import json
import struct
from typing import Any, Dict, Optional

class JsonProtocol:
    #256KB max size
    def __init__(self, max_message_bytes: int = 262144):
        self.max_message_bytes = max_message_bytes

    def send(self, sock: socket.socket, obj: Dict[str, Any]) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if len(data) > self.max_message_bytes:
            raise ValueError("json message is too large")

        #header purpose to define the data length
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)

    def recv(self, sock: socket.socket) -> Optional[Dict[str, Any]]:
        header = self._recv_exact(sock, 4)
        if header is None:
            return None

        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > self.max_message_bytes:
            raise ValueError("invalid json length: {}".format(length))

        payload = self._recv_exact(sock, length)
        if payload is None:
            return None

        return json.loads(payload.decode("utf-8"))

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data