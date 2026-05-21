from Crypto.Cipher import AES
from diffiehellman import DiffieHellman


class Cipher:
    """
    Cryptographic utility class for AES encryption/decryption and
    Diffie-Hellman key exchange.

    This class manages symmetric encryption operations for secure
    client-server communication in the system. It handles
    AES-EAX mode encryption/decryption and derives shared keys
    through the Diffie-Hellman key exchange protocol.

    Purpose:
        Provide a unified interface for cryptographic operations
        required in the secure communication layer between client
        and server.

    Usage:
        1. Generate DH key pair: dh, pk = Cipher.get_dh_public_key()
        2. Establish shared key: shared_key = Cipher.get_dh_shared_key(dh, remote_pk)
        3. Create cipher instance: cipher = Cipher(shared_key, NONCE)
        4. Encrypt/decrypt messages using aes_encrypt() and aes_decrypt()

    Security Considerations:
        - Uses AES-256 with EAX mode for authenticated encryption
        - Requires fixed NONCE for session-based communication
        - DH exchange uses Group 14 (2048-bit MODP group) for
          key derivation
        - Shared key is truncated to 32 bytes (256 bits) for AES-256
    """

    def __init__(self, key, nonce):
        """
        Initialize the Cipher with a derived shared key and nonce.

        Args:
            key (bytes): 32-byte AES key derived from Diffie-Hellman
                exchange.
            nonce (bytes): Fixed nonce value for EAX mode (typically 16 bytes).
        """
        self.key = key
        self.nonce = nonce

    def aes_encrypt(self, txt):
        """
        Encrypt plaintext using AES-256-EAX authenticated encryption.

        Args:
            txt (bytes): Plaintext data to encrypt (originally UTF-8 encoded JSON).

        Returns:
            bytes: Ciphertext (without authentication tag; tag is
                internally handled by EAX mode).
        """
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        ciphertext, tag = cipher.encrypt_and_digest(txt)
        return ciphertext

    def aes_decrypt(self, cipher_text):
        """
        Decrypt ciphertext using AES-256-EAX and return as UTF-8 string.

        Args:
            cipher_text (bytes): Encrypted data to decrypt.

        Returns:
            str: Decrypted and UTF-8 decoded plaintext.

        Raises:
            ValueError: If authentication verification fails or
                decoding is invalid.
        """
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        msg = cipher.decrypt(cipher_text)
        return msg.decode("utf-8")

    @staticmethod
    def get_dh_public_key():
        """
        Generate a new Diffie-Hellman key pair for the current instance.

        Returns:
            Tuple[DiffieHellman, bytes]: A tuple containing:
                - DiffieHellman object for shared key generation
                - Public key bytes (serialized)
        """
        dh = DiffieHellman(group=14, key_bits=540)
        pk = dh.get_public_key()
        return dh, pk

    @staticmethod
    def get_dh_shared_key(dh_1, pk_2, lngth=32):
        """
        Derive shared secret from local DH instance and remote public key.

        Args:
            dh_1 (DiffieHellman): Local DH instance containing private key.
            pk_2 (bytes): Remote party's public key.
            lngth (int): Number of bytes to truncate the shared secret to
                (default 32 for AES-256).

        Returns:
            bytes: Derived shared key of specified length.
        """
        dh_shared = dh_1.generate_shared_key(pk_2)
        return dh_shared[:lngth]
