import hashlib
import os
from opaque_utils import *
from tls_helper import *
import base64
from Hash2Curve import Hash2Curve
from pprint import pprint

# use a real database here instead
database = dict()

def opaque_demo():
    # === Registration ===
    # client -> server
    # ("Register", username)

    while True:
        username = input("Username: ")
        if username in database:
            print("Username is already taken")
        else:
            break

    pw = input("Password: ")
    # client -> server
    # ("Register", pw)

    s = random_z_q() # each user should have a unique salt
    rw = H(pw.encode() + power(h(pw.encode()), s).to_bytes())
    rw_key = KDF(rw)
    lpk_c, lsk_c = AKE_KeyGen()
    lpk_s, lsk_s = AKE_KeyGen()
    client_key_info = {"lpk_c": lpk_c, "lsk_c": lsk_c, "lpk_s": lpk_s}#(lpk_c, lsk_c, lpk_s)
    # server_k_bundle = {"lpk_c": lpk_c, "lpk_s": lpk_s, "lsk_s": lsk_s}

    print(f"lpk_c: {lpk_c}")
    print(f"lsk_c: {lsk_c}")
    print(f"lpk_s: {lpk_s}")
    enc_client_keys = AEAD_encrypt(rw_key, dict_to_bytes(client_key_info) )

    database[username] = {
        "user": username,
        "salt": s,
        "server_k_bundle": {
                    "lpk_c": lpk_c,
                    "lpk_s": lpk_s,
                    "lsk_s": lsk_s
                },
        "client_enc_k_bundle": enc_client_keys,
    }

    print("Registration successful")

    print("Waiting for Login request...")

    username = input("Username: ")
    pw = input("Password: ")

    h_pw = h(pw.encode())
    a = random_z_q()
    h_pw_a = power(h_pw, a)

    # client -> server
    # username, h_pw_a

    data = database[username]
    s = data["salt"]
    server_k_bundle = data["server_k_bundle"]
    client_enc_k_bundle = data["client_enc_k_bundle"]
    h_pw_a_s = power(h_pw_a, s)

    # server -> client
    # h_pw_a_s, client_enc_k_bundle

    a_inv = inverse(a)
    hp_pw_s = power(h_pw_a_s, a_inv)
    rw = H(pw.encode() + hp_pw_s.to_bytes())
    rw_key = KDF(rw)

    try:
        client_key_info = AEAD_decrypt(rw_key, *client_enc_k_bundle)
        client_key_info = bytes_to_dict(client_key_info)
    except:
        print("Invalid Tag. Password was incorrect!")
        exit(1)

    print(f"lpk_c: {client_key_info["lpk_c"]}")
    print(f"lsk_c: {client_key_info["lsk_c"]}")
    print(f"lpk_s: {client_key_info["lpk_s"]}\n")

    # AKE Stage
    epk_c, esk_c = AKE_KeyGen()

    # client -> server
    # epk_c

    epk_s, esk_s = AKE_KeyGen()
    b = lsk_s
    y = esk_s
    A = lpk_c
    X = epk_c
    SK_server = KServer(b, y, A, X)
    print("SK Server: " + SK_server.hex())

    # server -> client
    # epk_s

    a = client_key_info["lsk_c"]
    x = esk_c
    B = client_key_info["lpk_s"]
    Y = epk_s
    SK_client = KClient(a, x, B, Y)
    print("SK Client: " + SK_client.hex())

    key = hkdf_expand(SK_client, b"Key Confirmation", 32 * 2)
    ClientK_c, ClientK_s = key[:32], key[32:]
    client_mac_c = HMAC(ClientK_c, b"Client KC")
    client_mac_s = HMAC(ClientK_s, b"Server KS")

    # client -> server
    # client_mac_c

    key = hkdf_expand(SK_server, b"Key Confirmation", 32 * 2)
    ServerK_c, ServerK_s = key[:32], key[32:]
    server_mac_c = HMAC(ServerK_c, b"Client KC")
    server_mac_s = HMAC(ServerK_s, b"Server KS")

    assert server_mac_c == client_mac_c

    # server -> client
    # server_mac_s

    assert client_mac_s == server_mac_s

if __name__ == '__main__':
    opaque_demo()