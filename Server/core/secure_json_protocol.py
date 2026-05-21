import json
from typing import Any, Dict, Optional
import base64


class SecureJsonProtocol:
    """
    Encrypted messaging layer wrapping JsonProtocol with AES encryption.

    This protocol encrypts JSON messages using the provided Cipher
    object and wraps them in an encrypted envelope. All messages are
    wrapped in an outer JSON frame with type "ENC" and base64-encoded
    ciphertext.

    Purpose:
        Provide end-to-end encryption of application-level messages
        after successful Diffie-Hellman handshake.

    Message Format:
        {
            "type": "ENC",
            "payload": "<base64-encoded-ciphertext>"
        }

    Workflow:
        1. Receive outer envelope via JsonProtocol
        2. Extract and decode base64 payload
        3. Decrypt using Cipher.aes_decrypt()
        4. Parse inner JSON

    Attributes:
        inner (JsonProtocol): Underlying unencrypted protocol layer.
        cipher (Cipher): Cipher instance for encryption/decryption.
    """

    def __init__(self, inner_protocol, cipher):
        """
        Initialize secure protocol layer with encryption cipher.

        Args:
            inner_protocol (JsonProtocol): Underlying unencrypted protocol.
            cipher (Cipher): Initialized Cipher for message encryption.
        """
        self.inner = inner_protocol
        self.cipher = cipher

    def send(self, sock, obj: Dict[str, Any]) -> None:
        """
        Encrypt and send a JSON message via the secure channel.

        Args:
            sock (socket.socket): Connected TCP socket.
            obj (Dict[str, Any]): Message object to send (will be
                encrypted).
        """
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ct = self.cipher.aes_encrypt(plain)
        b64 = base64.b64encode(ct).decode("ascii")
        self.inner.send(sock, {"type": "ENC", "payload": b64})

    def recv(self, sock) -> Optional[Dict[str, Any]]:
        """
        Receive and decrypt a JSON message from the secure channel.

        Args:
            sock (socket.socket): Connected TCP socket.

        Returns:
            Optional[Dict[str, Any]]: Decrypted and parsed message,
                or None if connection closed.

        Raises:
            ValueError: If received message is not marked as "ENC" type.
        """
        wrapper = self.inner.recv(sock)  # here the real rcv from the socket!
        if wrapper is None:
            return None

        if str(wrapper.get("type", "")).upper() != "ENC":
            raise ValueError("non encrypted message received after handshake")

        b64 = wrapper.get("payload", "")
        ct = base64.b64decode(b64.encode("ascii"))
        plain_str = self.cipher.aes_decrypt(ct)
        return json.loads(plain_str)
