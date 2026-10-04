"""
Encrypted transport for the chat connection (used by both server.py and client.py).

Each connection starts with an ECDH key exchange (P-256); after that every frame is
AES-256-GCM. `binding` identifies this one connection: a login ticket is tied to it, so
nobody sitting between the two ends can pass a user's ticket on to another server.
"""

import socket
import struct
import threading
import time

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC

MAGIC = b"FC1"
PUBLIC_KEY_BYTES = 65            # uncompressed P-256 point
MAX_FRAME = 1024 * 1024          # 1 MB is far more than any chat message
HANDSHAKE_SECONDS = 10


class ChannelError(Exception):
    """The connection is closed, timed out, or sent something invalid."""


class SecureChannel:
    def __init__(self, sock, is_server, should_stop=None):
        self.sock = sock
        self.is_server = is_server
        self.binding = None
        self._should_stop = should_stop or (lambda: False)
        self._send_lock = threading.Lock()
        self._send_key = self._recv_key = None
        self._send_count = self._recv_count = 0

    # ------------------------------------------------------------------
    def _recv_exact(self, n, deadline=None):
        buf = b""
        while len(buf) < n:
            if deadline is not None and time.monotonic() > deadline:
                raise ChannelError("timed out")
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                if self._should_stop():
                    raise ChannelError("stopped")
                continue
            except OSError as e:
                raise ChannelError(str(e))
            if not chunk:
                raise ChannelError("connection closed")
            buf += chunk
        return buf

    def handshake(self):
        """Exchange public keys and derive the two AES keys. Raises ChannelError on failure."""
        deadline = time.monotonic() + HANDSHAKE_SECONDS
        mine = ECC.generate(curve="P-256")
        my_public = mine.public_key().export_key(format="SEC1")
        try:
            self.sock.sendall(MAGIC + my_public)
        except OSError as e:
            raise ChannelError(str(e))

        hello = self._recv_exact(len(MAGIC) + PUBLIC_KEY_BYTES, deadline)
        if hello[:len(MAGIC)] != MAGIC:
            raise ChannelError("not a Fast Connect 1.1 secure connection")
        their_public = hello[len(MAGIC):]
        try:
            theirs = ECC.import_key(their_public, curve_name="P-256")
        except ValueError:
            raise ChannelError("invalid public key")

        client_public, server_public = (their_public, my_public) if self.is_server else (my_public, their_public)
        transcript = SHA256.new(b"FastConnect-channel-v1" + client_public + server_public).digest()
        keys = key_agreement(
            eph_priv=mine, eph_pub=theirs,
            kdf=lambda secret: HKDF(secret, 64, transcript, SHA256, context=b"FastConnect-keys"))
        client_key, server_key = keys[:32], keys[32:]
        self._send_key, self._recv_key = (server_key, client_key) if self.is_server else (client_key, server_key)
        self.binding = transcript.hex()

    # ------------------------------------------------------------------
    def send(self, message):
        """Encrypt and send one text message."""
        data = message.encode("utf-8")
        if len(data) > MAX_FRAME - 16:
            raise ChannelError("message too large")
        with self._send_lock:
            # The counter is the nonce: never reused, and the other end expects the same order
            cipher = AES.new(self._send_key, AES.MODE_GCM, nonce=self._send_count.to_bytes(12, "big"))
            ciphertext, tag = cipher.encrypt_and_digest(data)
            self._send_count += 1
            try:
                self.sock.sendall(struct.pack(">I", len(ciphertext) + 16) + ciphertext + tag)
            except OSError as e:
                raise ChannelError(str(e))

    def recv(self):
        """Receive and decrypt one text message. Raises ChannelError when the connection ends."""
        length = struct.unpack(">I", self._recv_exact(4))[0]
        if length < 16 or length > MAX_FRAME:
            raise ChannelError("invalid frame size")
        frame = self._recv_exact(length)
        cipher = AES.new(self._recv_key, AES.MODE_GCM, nonce=self._recv_count.to_bytes(12, "big"))
        try:
            data = cipher.decrypt_and_verify(frame[:-16], frame[-16:])
        except ValueError:
            raise ChannelError("message failed its integrity check")
        self._recv_count += 1
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise ChannelError("invalid text")
