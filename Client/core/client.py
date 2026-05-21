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
    """
    Main client class for secure communication with the server.

    This class manages the complete lifecycle of client-server communication,
    including Diffie-Hellman handshake, authentication, file uploads, and
    medical image analysis requests. It handles threading synchronization
    for concurrent operations and manages secure encrypted messaging.

    Purpose:
        Provide a high-level, thread-safe API for all client operations
        required by the application.

    Workflow:
        1. Connect: Establish TCP socket and perform DH handshake
        2. Authenticate: Signup/Login with email verification and 2FA
        3. Upload: Send medical images in encrypted chunks
        4. Predict: Request AI inference on uploaded images
        5. History: Retrieve past analysis results
        6. Close: Gracefully close secure connection

    Architecture:
        - Socket Layer: Raw TCP communication
        - JsonProtocol: Framed JSON messaging
        - SecureJsonProtocol: Encrypted messages after handshake
        - Application Layer: Higher-level operations (auth, upload, predict)

    Threading:
        - Uses threading.Lock (_io_lock) to serialize socket I/O operations
        - Thread-safe for concurrent API calls
        - Automatically reconnects if needed

    Security:
        - Diffie-Hellman key exchange for session key derivation
        - AES-256-EAX authenticated encryption for all messages
        - File integrity verification via SHA-256 checksums
        - Chunked encrypted file transfer (65KB chunks)

    Attributes:
        host (str): Server hostname/IP.
        port (int): Server port.
        timeout_sec (int): Socket timeout in seconds.
        is_connected (bool): Connection state flag.
        CHUNK_SIZE (int): Size for file I/O operations (8192 bytes).
    """

    CHUNK_SIZE = 8192

    def __init__(self, host: str, port: int, timeout_sec: int = 600):
        """
        Initialize a new Client instance.

        Args:
            host (str): Server hostname or IP address.
            port (int): Server port number.
            timeout_sec (int): Socket timeout in seconds
                (default 600 = 10 minutes).
        """
        self.host = host
        self.port = port
        self.timeout_sec = timeout_sec

        self.sock: Optional[socket.socket] = None
        self.proto = JsonProtocol()
        self.secure: Optional[SecureJsonProtocol] = None
        self.is_connected = False

        self._io_lock = threading.Lock()

    def connect(self) -> None:
        """
        Establish secure connection with server via DH handshake.

        Performs the following steps:
        1. Create TCP socket and connect to server
        2. Receive server's DH public key
        3. Generate local DH key pair
        4. Compute shared secret
        5. Send client DH public key
        6. Verify secure channel with SECURE_OK message

        Raises:
            ConnectionError: If handshake fails or server response invalid.
        """
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
        """
        Connect to server only if not already connected.

        Useful for connection recovery after timeout or network errors.
        """
        if not self.is_connected or not self.sock or not self.secure:
            self.connect()

    def close(self) -> None:
        """
        Close the secure connection and clean up resources.

        Sends CLOSE message to server, closes socket, and clears
        internal state. Safe to call even if not connected.
        """
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
                        print(
                            "Socket exists but client is not marked as connected/secure"
                        )
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
        """
        Send a message via the established secure encrypted channel.

        Internal method for sending messages without acquiring the I/O lock.
        Caller must hold _io_lock. Uses SecureJsonProtocol to encrypt and
        frame the message before transmission.

        Args:
            obj (Dict[str, Any]): Message dictionary to encrypt and send.

        Raises:
            RuntimeError: If secure channel not established (connection failed
                or not yet initialized).
        """
        if not self.secure or not self.sock:
            raise RuntimeError("Secure channel not established")

    def _secure_recv_unlocked(self) -> Dict[str, Any]:
        """
        Receive and decrypt a message from the secure encrypted channel.

        Internal method for receiving messages without acquiring the I/O lock.
        Caller must hold _io_lock. Uses SecureJsonProtocol to receive framed
        data, decrypt, and parse JSON.

        Returns:
            Dict[str, Any]: Decrypted and parsed message object.        self.secure.send(self.sock, obj)


        Raises:
            RuntimeError: If secure channel not established.
            ConnectionError: If server closes connection (receives None from protocol).
        """
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
        Register a new user account with the server.

        Initiates signup flow. Server responds with either
        SIGNUP_VERIFY_REQUIRED (email verification needed) or ERROR.

        Args:
            username (str): Desired username.
            password (str): User password (should meet strength requirements).
            email (str): User email address (will receive verification code).

        Returns:
            dict: Server response with status and message.
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked(
                {
                    "type": "SIGNUP",
                    "username": username,
                    "password": password,
                    "email": email,
                }
            )
            return self._secure_recv_unlocked()

    def resend_email_code(self) -> Dict[str, Any]:
        """
        Request resend of email verification OTP code.

        Returns:
            dict: Server response indicating success or error.
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "RESEND_EMAIL_CODE"})
            return self._secure_recv_unlocked()

    def verify_email(self, otp_code: str) -> Dict[str, Any]:
        """
        Submit email verification code to complete signup.

        Args:
            otp_code (str): 6-digit OTP code received via email.

        Returns:
            dict: Server response (EMAIL_VERIFIED_OK or ERROR).
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "VERIFY_EMAIL", "otp_code": otp_code})
            return self._secure_recv_unlocked()

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate user with username and password.

        Triggers 2FA via email. Server responds with LOGIN_2FA_REQUIRED
        if email verified, or EMAIL_VERIFICATION_REQUIRED otherwise.

        Args:
            username (str): Username.
            password (str): Password.

        Returns:
            dict: Server response with authentication status.
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked(
                {"type": "LOGIN", "username": username, "password": password}
            )
            return self._secure_recv_unlocked()

    def resend_2fa_code(self) -> Dict[str, Any]:
        """
        Request resend of 2FA verification code via email.

        Returns:
            dict: Server response (RESEND_OK or ERROR).
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "RESEND_2FA_CODE"})
            return self._secure_recv_unlocked()

    def verify_2fa(self, otp_code: str) -> Dict[str, Any]:
        """
        Complete login by submitting 2FA code.

        Args:
            otp_code (str): 6-digit 2FA code received via email.

        Returns:
            dict: Server response (LOGIN_OK or ERROR).

        Once successful, user can upload and analyze medical images.
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "VERIFY_2FA", "otp_code": otp_code})
            return self._secure_recv_unlocked()

    # -------------------------
    # App API
    # -------------------------
    def get_history(self) -> Dict[str, Any]:
        """
        Retrieve user's scan history (past analysis results).

        Returns:
            dict: Response with type HISTORY_OK and list of past scans.
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "HISTORY"})
            return self._secure_recv_unlocked()

    def predict(self, request_id: str) -> Dict[str, Any]:
        """
        Request AI inference on previously uploaded medical image.

        Args:
            request_id (str): Unique ID from upload() return value.

        Returns:
            dict: Response with PREDICT_OK and prediction results
                (label, probability, latency).
        """
        with self._io_lock:
            self.connect_if_needed()
            self._secure_send_unlocked({"type": "PREDICT", "request_id": request_id})
            return self._secure_recv_unlocked()

    def upload(
        self,
        file_path: str,
        patient_id: str,
        request_id: Optional[str] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Upload a medical scan file to the server using secure encrypted protocol.

        The function prepares file metadata, transmits the file in encrypted
        chunks with progress tracking, and returns a request ID for later
        prediction requests.

        Args:
            file_path (str): Full path to the medical image file (PNG, JPG, etc.).
            patient_id (str): Unique patient identifier associated with scan.
            request_id (Optional[str]): Custom request ID (auto-generated if None).
            on_progress (Optional[Callable]): Callback for upload progress.
                Receives (bytes_sent, total_bytes) and should be non-blocking.

        Returns:
            dict: Server response containing:
                - type: "UPLOAD_OK" or "ERROR"
                - request_id: ID for future predict() calls
                - message: Status message

        Raises:
            FileNotFoundError: If file_path does not exist.
        """
        with self._io_lock:
            self.connect_if_needed()

            meta = self._prepare_upload_metadata(file_path, request_id)

            self._secure_send_unlocked(
                {
                    "type": "UPLOAD",
                    "request_id": meta["request_id"],
                    "file_size": meta["file_size"],
                    "ext": meta["ext"],
                    "sha256": meta["sha256"],
                    "patient_id": patient_id,
                }
            )

            ready = self._secure_recv_unlocked()
            if ready.get("type") == "ERROR":
                return ready
            if (
                ready.get("type") != "READY"
                or ready.get("request_id") != meta["request_id"]
            ):
                return {"type": "ERROR", "message": f"Bad READY: {ready}"}

            self._stream_encrypted_file(
                self.sock, file_path, meta["file_size"], on_progress
            )

            resp = self._secure_recv_unlocked()
            return resp

    def _prepare_upload_metadata(
        self, file_path: str, req_id: Optional[str]
    ) -> Dict[str, Any]:
        """
        Compute file metadata needed for upload protocol.

        Args:
            file_path (str): Path to file to upload.
            req_id (Optional[str]): Optional request ID (generated if None).

        Returns:
            dict: Metadata containing request_id, file_size, ext, sha256.
        """
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
            "sha256": sha.hexdigest(),
        }

    def _stream_encrypted_file(
        self,
        sock: socket.socket,
        path: str,
        total_size: int,
        on_progress: Optional[Callable[[int, int], None]],
    ) -> None:
        """
        Stream file to server in encrypted chunks with progress tracking.

        Each chunk is encrypted via SecureJsonProtocol (inner AES) and
        prefixed with its length.

        Args:
            sock (socket.socket): Connected socket.
            path (str): Path to file to stream.
            total_size (int): Total file size in bytes.
            on_progress (Optional[Callable]): Progress callback.
        """
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
