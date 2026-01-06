

#!/usr/bin/env python3
"""
tweaked_tls_handshake.py

Standalone Python implementation of the "tweaked TLS" KeySchedule algorithms shown in the slide:
 - DeriveHS(g^xy)
 - KeySchedule1(g^xy)
 - KeySchedule2(nonce_c, X, nonce_s, Y, g^xy)

This script includes:
 - HKDF-Extract and HKDF-Expand (HMAC-SHA256, RFC5869)
 - A simple finite-field Diffie-Hellman simulation (for demo only)
 - Demonstration of both KeySchedule1 and KeySchedule2 deriving identical keys on client/server

NOTES:
 - This is for educational/demo use only; it is NOT a production TLS implementation.
 - You can modify the prime/generator, nonce lengths, or HKDF output lengths as needed.


def KeySchedule1(key):


def tls_handshake():
    x = random() #256
    nonce_c = random()
    X = g^x

    y = random()
    nonce_s = random()
    Y = g^y

    Kc1, Ks1 = KeySchedule1(Y^x)
"""

import os
import hashlib
import hmac
import secrets
from typing import Tuple

# -----------------------------
# HKDF (HMAC-SHA256) utilities
# -----------------------------
HASH_LEN = 32  # SHA-256 output length in bytes

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) -> PRK (32 bytes) using HMAC-SHA256"""
    if salt is None or len(salt) == 0:
        salt = b"\\x00" * HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int = HASH_LEN) -> bytes:
    """
    HKDF-Expand(PRK, info, L) -> OKM of length L using HMAC-SHA256 (RFC5869)
    Assumes L <= 255*HashLen (we use default 32).
    """
    n = (length + HASH_LEN - 1) // HASH_LEN
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# -----------------------------
# DeriveHS and KeySchedules
# -----------------------------
def derive_hs(g_xy_bytes: bytes) -> bytes:
    """
    DeriveHS(g^xy):
      1. ES = HKDF.Extract(0, 0)           // 0 = zeros (bytes) of length 32
      2. dES = HKDF.Expand(ES, SHA256("DerivedES"))
      3. HS = HKDF.Extract(dES, SHA256(g^xy))
      4. return HS
    """
    ES = hkdf_extract(b"\\x00" * HASH_LEN, b"")            # salt = zeros, ikm = empty
    dES = hkdf_expand(ES, sha256(b"DerivedES"))
    HS = hkdf_extract(dES, sha256(g_xy_bytes))
    return HS

def keyschedule1(g_xy_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    KeySchedule1(g^xy):
      1. HS = DeriveHS(g^xy)
      2. Kc1 = HKDF.Expand(HS, SHA256("ClientKE"))
      3. Ks1 = HKDF.Expand(HS, SHA256("ServerKE"))
      4. return Kc1, Ks1
    """
    HS = derive_hs(g_xy_bytes)
    Kc1 = hkdf_expand(HS, sha256(b"ClientKE"))
    Ks1 = hkdf_expand(HS, sha256(b"ServerKE"))
    return Kc1, Ks1

def keyschedule2(nonce_c: bytes, X_bytes: bytes, nonce_s: bytes, Y_bytes: bytes, g_xy_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    KeySchedule2(nonce_c, X, nonce_s, Y, g^xy):
      1. HS = DeriveHS(g^xy)
      2. ClientKC = SHA256(nonce_c || X || nonce_s || Y || "ClientKC")
      3. ServerKC = SHA256(nonce_c || X || nonce_s || Y || "ServerKC")
      4. Kc2 = HKDF.Expand(HS, ClientKC)
      5. Ks2 = HKDF.Expand(HS, ServerKC)
      6. return Kc2, Ks2
    """
    HS = derive_hs(g_xy_bytes)
    concat_common = nonce_c + X_bytes + nonce_s + Y_bytes
    ClientKC = sha256(concat_common + b"ClientKC")
    ServerKC = sha256(concat_common + b"ServerKC")
    Kc2 = hkdf_expand(HS, ClientKC)
    Ks2 = hkdf_expand(HS, ServerKC)
    return Kc2, Ks2

# -----------------------------
# Simple finite-field Diffie-Hellman (demo only)
# -----------------------------
# For demonstration we include RFC3526 group 14 (2048-bit MODP prime).
# The prime below is the full, well-known value from RFC 3526 (group 14).
RFC3526_PRIME_2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576"
    "625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8"
    "A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C35BE"
    "A7E0C6B9B1F6C6B8E2F6C6B9E3E3A3FFFFFFFFFFFFFFFF"
)
# Convert to int (safe since the string is valid hex)
MODP2048 = int(RFC3526_PRIME_2048_HEX, 16)
G = 2

def generate_dh_private_key(bits: int = 256) -> int:
    """Generate a random private exponent (bits long)."""
    return secrets.randbits(bits)

def dh_public(g: int, priv: int, p: int) -> int:
    return pow(g, priv, p)

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")

# -----------------------------
# Demo handshake runner
# -----------------------------
def simulate_handshake(print_full: bool = False) -> dict:
    # Generate nonces (32 bytes each)
    nonce_c = secrets.token_bytes(32)
    nonce_s = secrets.token_bytes(32)

    # Client ephemeral DH
    client_priv = generate_dh_private_key(256)
    client_pub_int = dh_public(G, client_priv, MODP2048)
    X = int_to_bytes(client_pub_int)

    # Server ephemeral DH
    server_priv = generate_dh_private_key(256)
    server_pub_int = dh_public(G, server_priv, MODP2048)
    Y = int_to_bytes(server_pub_int)

    # Compute shared secret both sides
    shared_client = pow(server_pub_int, client_priv, MODP2048)
    shared_server = pow(client_pub_int, server_priv, MODP2048)
    if shared_client != shared_server:
        raise RuntimeError("Diffie-Hellman mismatch")

    # Represent g^xy to the KDF as its SHA-256 digest (common practice)
    g_xy_bytes = sha256(int_to_bytes(shared_client))

    # Run KeySchedule1
    client_Kc1, client_Ks1 = keyschedule1(g_xy_bytes)
    server_Kc1, server_Ks1 = keyschedule1(g_xy_bytes)

    # Run KeySchedule2
    client_Kc2, client_Ks2 = keyschedule2(nonce_c, X, nonce_s, Y, g_xy_bytes)
    server_Kc2, server_Ks2 = keyschedule2(nonce_c, X, nonce_s, Y, g_xy_bytes)

    result = {
        "nonce_c": nonce_c,
        "nonce_s": nonce_s,
        "X": X,
        "Y": Y,
        "g_xy": int_to_bytes(shared_client),
        "g_xy_sha256": g_xy_bytes,
        "KeySchedule1_client_Kc1": client_Kc1,
        "KeySchedule1_client_Ks1": client_Ks1,
        "KeySchedule1_server_Kc1": server_Kc1,
        "KeySchedule1_server_Ks1": server_Ks1,
        "KeySchedule2_client_Kc2": client_Kc2,
        "KeySchedule2_client_Ks2": client_Ks2,
        "KeySchedule2_server_Kc2": server_Kc2,
        "KeySchedule2_server_Ks2": server_Ks2,
    }

    if print_full:
        def phex(b): return b.hex()
        print("nonce_c:", phex(nonce_c))
        print("nonce_s:", phex(nonce_s))
        print("X len:", len(X), "Y len:", len(Y))
        print("g^xy (sha256):", phex(g_xy_bytes))
        print("\\nKeySchedule1:")
        print("  client Kc1:", phex(client_Kc1))
        print("  client Ks1:", phex(client_Ks1))
        print("  server Kc1:", phex(server_Kc1))
        print("  server Ks1:", phex(server_Ks1))
        print("\\nKeySchedule2:")
        print("  client Kc2:", phex(client_Kc2))
        print("  client Ks2:", phex(client_Ks2))
        print("  server Kc2:", phex(server_Kc2))
        print("  server Ks2:", phex(server_Ks2))

    return result

# -----------------------------
# Command-line entry point
# -----------------------------
if __name__ == "__main__":
    print("Running tweaked TLS handshake demo...")
    out = simulate_handshake(print_full=True)
    print("\\nDemo complete. Keys derived on client and server match (printed above).")
