from tls_helper import *

# Post-quantum primitives
from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44




# =========================
# PQ-TLS Handshake
# =========================

def pq_tls_handshake():
    #print("=== PQ-TLS Handshake (TLS-ordered) ===")

    # ============================================================
    # 1. ClientHello  (Client → Server)
    # ============================================================
    nonce_c = secrets.token_bytes(32)
    pk_c, sk_c = ML_KEM_512.keygen()

    # Client sends: nonce_c, pk_c


    # ============================================================
    # 2. ServerHello  (Server → Client)
    # ============================================================
    nonce_s = secrets.token_bytes(32)

    server_shared_secret, ct_kem = ML_KEM_512.encaps(pk_c)

    # Server sends: nonce_s, ct_kem


    # ============================================================
    # 3. Client derives shared secret (implicit after ServerHello)
    # ============================================================
    client_shared_secret = ML_KEM_512.decaps(sk_c, ct_kem)
    assert server_shared_secret == client_shared_secret


    # ============================================================
    # 4. Handshake key schedule (after ServerHello)
    # ============================================================

    # TODO: change to be signed by CA
    # Long-term authentication key (certificate)
    pk_s, sk_s = ML_DSA_44.keygen()
    cert = pk_s

    kc1_s, ks1_s = KeySchedule1(server_shared_secret)
    kc1_c, ks1_c = KeySchedule1(client_shared_secret)

    kc2_s, ks2_s = KeySchedule2(
        nonce_c, pk_c, nonce_s, pk_s, server_shared_secret
    )
    kc2_c, ks2_c = KeySchedule2(
        nonce_c, pk_c, nonce_s, pk_s, client_shared_secret
    )


    # ============================================================
    # 5. Server authentication flight
    #    EncryptedExtensions | Certificate | CertificateVerify | Finished
    #    (Server → Client, encrypted under ks1)
    # ============================================================

    transcript_hash = sha256(
        nonce_c + pk_c + nonce_s + pk_s + cert
    ).digest()

    # CertificateVerify
    sigma = ML_DSA_44.sign(sk_s, transcript_hash)

    # Finished
    mac_s = hmac_sign(
        ks2_s,
        sha256(nonce_c + pk_c + nonce_s + pk_s + sigma + cert + b"ServerMAC").digest()
    )

    kc3_s, ks3_s = KeySchedule3(
        nonce_c, pk_c, nonce_s, pk_s,
        server_shared_secret, sigma, cert, mac_s
    )

    server_flight = cert + sigma + mac_s #repr((cert, sigma, mac_s)).encode()
    aad = b"PQ-TLS-ServerFlight"

    iv, ct, tag = aes_gcm_encrypt(ks1_s, server_flight, aad)

    # Server sends: AEAD(ks1_s, {cert, sigma, mac_s})


    # ============================================================
    # 6. Client processes server flight
    # ============================================================
    decrypted = aes_gcm_decrypt(ks1_c, iv, ct, aad, tag)
    cert_c = decrypted[:1312]
    sigma_c = decrypted[1312:3732]
    mac_s_c = decrypted[3732:]

    assert ML_DSA_44.verify(cert_c, transcript_hash, sigma_c)
    assert hmac_verify(
        ks2_c,
        sha256(nonce_c + pk_c + nonce_s + pk_s + sigma + cert + b"ServerMAC").digest(),
        mac_s_c
    )


    # ============================================================
    # 7. Client Finished  (Client → Server, encrypted under kc1)
    # ============================================================
    mac_c = hmac_sign(
        kc2_c,
        sha256(nonce_c + pk_c + nonce_s + pk_s + sigma_c + cert_c + b"ClientMAC").digest()
    )

    iv, ct, tag = aes_gcm_encrypt(
        kc1_c,
        mac_c,
        b"PQ-TLS-ClientFinish"
    )

    # Client sends: AEAD(kc1_c, mac_c)


    # ============================================================
    # 8. Server verifies Client Finished
    # ============================================================
    decrypted = aes_gcm_decrypt(
        kc1_s,
        iv,
        ct,
        b"PQ-TLS-ClientFinish",
        tag
    )

    assert hmac_verify(
        kc2_s,
        sha256(nonce_c + pk_c + nonce_s + pk_s + sigma + cert + b"ClientMAC").digest(),
        decrypted
    )


    # ============================================================
    # 9. Application traffic keys
    # ============================================================
    kc3_c, ks3_c = KeySchedule3(
        nonce_c, pk_c, nonce_s, pk_s,
        client_shared_secret, sigma_c, cert_c, mac_s_c
    )

    assert kc3_c == kc3_s
    assert ks3_c == ks3_s

    #print("✓ PQ-TLS handshake completed")
    #print("✓ Application traffic keys established")



if __name__ == "__main__":
    pq_tls_handshake()
