import socket
import json
import struct
from typing import Any, Dict, Optional


class JsonProtocol:
    """
    Low-level protocol handler for structured JSON message exchange
    over TCP sockets.

    This protocol implements a framing mechanism where each message
    is prefixed with a 4-byte big-endian length header, followed
    by JSON-encoded payload. It serves as the foundation for
    SecureJsonProtocol.

    Purpose:
        Handle serialization, framing, and transmission of JSON
        messages over unreliable TCP connections without encryption.

    Message Format:
        [4-byte length header (big-endian)] [JSON payload (UTF-8)]

    Thread Safety:
        Not thread-safe. External synchronization required when
        used concurrently.

    Attributes:
        max_message_bytes (int): Maximum allowed message size
            (default 256 KB).
    """

    def __init__(self, max_message_bytes: int = 262144):
        """
        Initialize JSON protocol with configured message size limit.

        Args:
            max_message_bytes (int): Maximum message size in bytes
                (default 262144 = 256 KB). Prevents DOS attacks.
        """
        self.max_message_bytes = max_message_bytes

    def send(self, sock: socket.socket, obj: Dict[str, Any]) -> None:
        """
        Serialize and send a JSON message over the socket.

        Args:
            sock (socket.socket): Connected TCP socket.
            obj (Dict[str, Any]): Dictionary to serialize and send.

        Raises:
            ValueError: If serialized message exceeds max_message_bytes.
        """
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if len(data) > self.max_message_bytes:
            raise ValueError("json message is too large")

        # header purpose to define the data length
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)

    def recv(self, sock: socket.socket) -> Optional[Dict[str, Any]]:
        """
        Receive and parse a JSON message from the socket.

        Args:
            sock (socket.socket): Connected TCP socket.

        Returns:
            Optional[Dict[str, Any]]: Parsed JSON object, or None if
                connection closed.

        Raises:
            ValueError: If message length is invalid or out of bounds.
        """
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
        """
        Receive exactly n bytes from socket, blocking if necessary.

        Args:
            sock (socket.socket): Connected TCP socket.
            n (int): Number of bytes to receive.

        Returns:
            Optional[bytes]: Exactly n bytes, or None if connection
                closed before receiving all bytes.
        """
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
