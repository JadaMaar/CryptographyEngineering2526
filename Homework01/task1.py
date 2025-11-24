from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================================
# ECDH key generation and shared secret
# ============================================================
def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# ============================================================
# Ed25519 key generation (for signing)
# ============================================================
def generate_signing_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# ============================================================
# Helper: serialize public keys to bytes for signing
# ============================================================
def serialize_public_key(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# ============================================================
# Authenticated ECDH key exchange (SIGMA-like)
# ============================================================
def authenticated_ecdh():
    # Step 1. Long-term signing keys (Ed25519)
    alice_sig_sk, alice_sig_pk = generate_signing_key_pair()
    bob_sig_sk, bob_sig_pk = generate_signing_key_pair()

    # Step 2. Ephemeral ECDH keys
    alice_dh_sk, alice_dh_pk = generate_ecdh_key_pair()
    bob_dh_sk, bob_dh_pk = generate_ecdh_key_pair()

    # Step 3. Serialize DH public keys
    X = serialize_public_key(alice_dh_pk)
    Y = serialize_public_key(bob_dh_pk)

    # Step 4. Bob signs (X || Y) and sends σ_B
    sigma_B = bob_sig_sk.sign(X + Y)

    # Step 5. Alice verifies Bob’s signature
    try:
        bob_sig_pk.verify(sigma_B, X + Y)
        print("✅ Alice verified Bob's signature.")
    except Exception:
        raise ValueError("❌ Invalid signature from Bob!")

    # Step 6. Alice signs (X || Y) and sends σ_A
    sigma_A = alice_sig_sk.sign(X + Y)

    # Step 7. Bob verifies Alice’s signature
    try:
        alice_sig_pk.verify(sigma_A, X + Y)
        print("✅ Bob verified Alice's signature.")
    except Exception:
        raise ValueError("❌ Invalid signature from Alice!")

    # Step 8. Compute shared secret and derive session key
    K_alice = compute_shared_secret(alice_dh_sk, bob_dh_pk)
    K_bob = compute_shared_secret(bob_dh_sk, alice_dh_pk)
    assert K_alice == K_bob, "Shared secrets differ!"

    # Derive a 256-bit session key via HKDF
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"authenticated ECDH",
    ).derive(K_alice)

    print("🔑 Shared secret (raw):", K_alice.hex())
    print("🔐 Session key (derived):", key.hex())

# ============================================================
# Run the protocol
# ============================================================
if __name__ == "__main__":
    authenticated_ecdh()
