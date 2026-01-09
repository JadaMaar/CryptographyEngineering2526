from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44

from tls_helper import *



def kem_tls_demo():
    nonce_c = secrets.token_bytes(32)
    ek, dk = ML_KEM_512.keygen()

    # ==========================================
    # client sends nonce_c, ek to the server   |
    # ==========================================
    print(f"client -> server\n nonce_c: {nonce_c}\n ek: {ek}\n")

    auth_pk, auth_sk = ML_DSA_44.keygen()

    nonce_s = secrets.token_bytes(32)
    sigma = secrets.token_bytes(32)
    server_pk_kem, server_sk_kem = ML_KEM_512.keygen()
    server_cert = ML_DSA_44.sign(auth_sk, server_pk_kem)
    server_K1, ct1 = ML_KEM_512.encaps(ek)

    # ==========================================
    # server sends nonce_s, ct to the client   |
    # ==========================================
    print(f"server -> client\n nonce_s: {nonce_s}\n ct: {ct1}\n")

    server_kc1, server_ks1 = KeySchedule1(server_K1)
    # server_kc2, server_ks2 = KeySchedule2(nonce_c, pk_c_bytes, nonce_s, pk_s_bytes, derived_key_server)

    associated_data = f"Alice, Bob, {server_pk_kem}, {ek}".encode()
    iv, ciphertext, tag = aes_gcm_encrypt(server_ks1, server_cert, associated_data)

    # ===============================================================
    # server sends iv, ciphertext, tag, server_pk_kem to the client |
    # ===============================================================
    print(f"server -> client\n iv: {iv}\n ciphertext: {ciphertext}\n tag: {tag}\n server_pk_kem: {server_pk_kem}\n")

    client_K1 = ML_KEM_512.decaps(dk, ct1)
    assert server_K1 == client_K1
    client_kc1, client_ks1 = KeySchedule1(client_K1)

    client_decrypted_message = aes_gcm_decrypt(client_ks1, iv, ciphertext, associated_data, tag)
    client_cert = client_decrypted_message
    assert ML_DSA_44.verify(auth_pk, server_pk_kem, client_cert)

    client_K2, ct2 = ML_KEM_512.encaps(server_pk_kem)
    iv, ciphertext, tag = aes_gcm_encrypt(client_kc1, ct2, associated_data)

    # ================================================
    # client sends iv, ciphertext, tag to the server |
    # ================================================
    print(f"client -> server\n iv: {iv}\n ciphertext: {ciphertext}\n tag: {tag}\n")

    # server
    server_decrypted_message = aes_gcm_decrypt(server_kc1, iv, ciphertext, associated_data, tag)
    server_K2 = ML_KEM_512.decaps(server_sk_kem, server_decrypted_message)
    server_combined_keys = hkdf_extract(server_K1, server_K2)

    # client
    client_combined_keys = hkdf_extract(client_K1, client_K2)
    client_K2c, client_K2s = KeySchedule2(nonce_c, ek, nonce_s, server_pk_kem, client_combined_keys)
    client_mac = hmac_sign(client_K2c, sha256(nonce_c + ek + nonce_s + server_pk_kem + sigma + client_cert + b"ClientMAC").digest())
    iv, ciphertext, tag = aes_gcm_encrypt(client_K2c, client_mac, associated_data)

    # ================================================
    # client sends iv, ciphertext, tag to the server |
    # ================================================
    print(f"client -> server\n iv: {iv}\n ciphertext: {ciphertext}\n tag: {tag}\n")

    server_K2c, server_K2s = KeySchedule2(nonce_c, ek, nonce_s, server_pk_kem, server_combined_keys)
    server_decrypted_message = aes_gcm_decrypt(server_K2c, iv, ciphertext, associated_data, tag)
    client_mac_s = server_decrypted_message
    assert hmac_verify(
        server_K2c,
        sha256(nonce_c + ek + nonce_s + server_pk_kem + sigma + client_decrypted_message + b"ClientMAC").digest(),
        client_mac_s)
    server_mac = hmac_sign(server_K2s, sha256(nonce_c + ek + nonce_s + server_pk_kem + sigma + server_cert + b"ServerMAC").digest())
    iv, ciphertext, tag = aes_gcm_encrypt(server_K2s, server_mac, associated_data)

    # ================================================
    # server sends iv, ciphertext, tag to the client |
    # ================================================
    print(f"server -> client\n iv: {iv}\n ciphertext: {ciphertext}\n tag: {tag}\n")

    client_decrypted_message = aes_gcm_decrypt(client_K2s, iv, ciphertext, associated_data, tag)
    server_mac_c = client_decrypted_message
    assert hmac_verify(
        client_K2s,
        sha256(nonce_c + ek + nonce_s + server_pk_kem + sigma + client_cert + b"ServerMAC").digest(),
        server_mac_c)

    # both generate K3
    # client
    kc3_c, ks3_c = KeySchedule3(
        nonce_c, ek, nonce_s, server_pk_kem,
        client_combined_keys, sigma, client_cert, server_mac_c
    )

    # server
    kc3_s, ks3_s = KeySchedule3(
        nonce_c, ek, nonce_s, server_pk_kem,
        server_combined_keys, sigma, server_cert, server_mac
    )

    assert kc3_c == kc3_s
    assert ks3_c == ks3_s



if __name__ == '__main__':
    kem_tls_demo()