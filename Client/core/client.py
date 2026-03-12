from .constants import NONCE
from .json_protocol import JsonProtocol
from .secure_json_protocol import SecureJsonProtocol
from .cipher import Cipher

import socket
import struct
import base64
import hashlib
import os
import uuid
import threading
from typing import Dict, Any, Optional, Callable


class Client:
    CHUNK_SIZE = 65536

    def __init__(self, host: str, port: int, timeout_sec: int = 600):
        self.host = host
        self.port = port
        self.timeout_sec = timeout_sec

        self.sock: Optional[socket.socket] = None
        self.proto = JsonProtocol()
        self.secure: Optional[SecureJsonProtocol] = None
        self.is_connected = False

        self._io_lock = threading.Lock()

    def connect(self) -> None:
        if self.is_connected:
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout_sec)
            self.sock.connect((self.host, self.port))

            msg = self.proto.recv(self.sock)
            if not msg or msg.get("type") != "DH_SERVER_PK":
                raise ConnectionError("Handshake failed: Invalid server hello")

            server_pk_bytes = base64.b64decode(msg["pk"])
            client_dh, client_pk = Cipher.get_dh_public_key()
            shared_key = Cipher.get_dh_shared_key(client_dh, server_pk_bytes, lngth=32)

            client_pk_b64 = base64.b64encode(client_pk).decode("ascii")
            self.proto.send(self.sock, {"type": "DH_CLIENT_PK", "pk": client_pk_b64})

            cipher = Cipher(shared_key, NONCE)
            self.secure = SecureJsonProtocol(self.proto, cipher)

            ok_msg = self._secure_recv_unlocked()
            if ok_msg.get("type") != "SECURE_OK":
                raise ConnectionError(f"Secure handshake failed: {ok_msg}")

            self.is_connected = True

        except Exception as e:
            self.close()
            raise ConnectionError(f"Failed to connect: {e}")

    def connect_if_needed(self) -> None:
        if not self.is_connected or not self.sock or not self.secure:
            self.connect()

    def close(self) -> None:
        try:
            if self.sock:
                try:
                    if self.is_connected and self.secure:
                        try:
                            print("Sending CLOSE message to server...")
                            self.secure.send(self.sock, {"type": "CLOSE"})
                            print("CLOSE message sent")
                        except Exception as e:
                            print("Failed sending CLOSE:", e)
                    else:
                        print("Socket exists but client is not marked as connected/secure")
                finally:
                    try:
                        self.sock.close()
                        print("Socket closed")
                    except Exception as e:
                        print("Socket close failed:", e)
        finally:
            self.sock = None
            self.secure = None
            self.is_connected = False
            print("Client state cleared")

    # -------------------------
    # Secure send/recv
    # -------------------------
    def _secure_send_unlocked(self, obj: Dict[str, Any]) -> None:
        if not self.secure or not self.sock:
            raise RuntimeError("Secure channel not established")
        self.secure.send(self.sock, obj)

    def _secure_recv_unlocked(self) -> Dict[str, Any]:
        if not self.secure or not self.sock:
            raise RuntimeError("Secure channel not established")
        msg = self.secure.recv(self.sock)
        if msg is None:
            raise ConnectionError("Server closed connection")
        return msg

    # -------------------------
    # Auth flows
    # -------------------------
    def signup(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """
        Server response: SIGNUP_VERIFY_REQUIRED or ERROR
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({
                "type": "SIGNUP",
                "username": username,
                "password": password,
                "email": email
            })
            return self._secure_recv_unlocked()

    def resend_email_code(self) -> Dict[str, Any]:
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "RESEND_EMAIL_CODE"})
            return self._secure_recv_unlocked()

    def verify_email(self, otp_code: str) -> Dict[str, Any]:
        """
        Server response: EMAIL_VERIFIED_OK or ERROR
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({
                "type": "VERIFY_EMAIL",
                "otp_code": otp_code
            })
            return self._secure_recv_unlocked()

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Server response: LOGIN_2FA_REQUIRED or ERROR
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({
                "type": "LOGIN",
                "username": username,
                "password": password
            })
            return self._secure_recv_unlocked()

    def resend_2fa_code(self) -> Dict[str, Any]:
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "RESEND_2FA_CODE"})
            return self._secure_recv_unlocked()

    def verify_2fa(self, otp_code: str) -> Dict[str, Any]:
        """
        Server response: LOGIN_OK or ERROR
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({
                "type": "VERIFY_2FA",
                "otp_code": otp_code
            })
            return self._secure_recv_unlocked()

    # -------------------------
    # App API
    # -------------------------
    def get_history(self) -> Dict[str, Any]:
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "HISTORY"})
            return self._secure_recv_unlocked()

    def predict(self, request_id: str) -> Dict[str, Any]:
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "PREDICT", "request_id": request_id})
            return self._secure_recv_unlocked()

    def upload(
        self,
        file_path: str,
        patient_id: str,
        request_id: Optional[str] = None,
        on_progress: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        with self._io_lock:
            self.connect_if_needed()

            meta = self._prepare_upload_metadata(file_path, request_id)

            self._secure_send_unlocked({
                "type": "UPLOAD",
                "request_id": meta["request_id"],
                "file_size": meta["file_size"],
                "ext": meta["ext"],
                "sha256": meta["sha256"],
                "patient_id": patient_id,
            })

            ready = self._secure_recv_unlocked()
            if ready.get("type") == "ERROR":
                return ready
            if ready.get("type") != "READY" or ready.get("request_id") != meta["request_id"]:
                return {"type": "ERROR", "message": f"Bad READY: {ready}"}

            self._stream_encrypted_file(self.sock, file_path, meta["file_size"], on_progress)

            resp = self._secure_recv_unlocked()
            return resp

    def _prepare_upload_metadata(self, file_path: str, req_id: Optional[str]) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)

        file_size = os.path.getsize(file_path)
        req_id = req_id if req_id else uuid.uuid4().hex
        ext = os.path.splitext(file_path)[1].lstrip(".").lower() or "bin"

        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)

        return {
            "request_id": req_id,
            "file_size": file_size,
            "ext": ext,
            "sha256": sha.hexdigest()
        }

    def _stream_encrypted_file(
        self,
        sock: socket.socket,
        path: str,
        total_size: int,
        on_progress: Optional[Callable[[int, int], None]]
    ) -> None:
        if not self.secure:
            raise RuntimeError("Secure channel not established")

        read_size = 65536
        sent = 0

        with open(path, "rb") as f:
            while True:
                raw_chunk = f.read(read_size)
                if not raw_chunk:
                    break

                b64_chunk = base64.b64encode(raw_chunk)
                encrypted_chunk = self.secure.cipher.aes_encrypt(b64_chunk)

                header = struct.pack(">I", len(encrypted_chunk))
                sock.sendall(header + encrypted_chunk)

                sent += len(raw_chunk)
                if on_progress:
                    on_progress(sent, total_size)