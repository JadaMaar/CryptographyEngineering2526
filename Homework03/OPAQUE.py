import hashlib
import os
from opaque_utils import *
import base64
from Hash2Curve import Hash2Curve
from pprint import pprint

# use a real database here instead
database = dict()

def opaque_demo():
    # === Registration ===
    while True:
        username = input("Username: ")
        if username in database:
            print("Username is already taken")
        else:
            break

    pw = input("Password: ")

    # client -> server
    # ("Register", username, pw)

    s = random_z_q() # each user should have a unique salt
    rw = H(pw.encode() + power(h(pw.encode()), s).to_bytes()) # iterate_hash_with_salt(pw, s, 10)# hashlib.sha256(pw.encode() + s).hexdigest()
    rw_key = KDF(rw)
    lpk_c, lsk_c = AKE_KeyGen()
    lpk_s, lsk_s = AKE_KeyGen()
    client_key_info = {"lpk_c": lpk_c, "lsk_c": lsk_c, "lpk_s": lpk_s}#(lpk_c, lsk_c, lpk_s)

    print(f"lpk_c: {lpk_c}")
    print(f"lsk_c: {lsk_c}")
    print(f"lpk_s: {lpk_s}")
    #pprint(client_key_info)
    enc_client_keys = AEAD_encrypt(rw_key, dict_to_bytes(client_key_info) )

    # pprint(bytes_to_dict(dict_to_bytes(client_key_info)))

    # Then the server store {
    # user: Username // … as index
    # salt: 𝒔
    # server_k_bundle: 𝒍𝒑𝒌𝒄 , 𝒍𝒑𝒌𝒔 ,𝒍𝒔𝒌𝒔
    # client_enc_k_bundle: enc_client_keys
    # … // Auxiliary information
    # } in the password database
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


if __name__ == '__main__':
    opaque_demo()