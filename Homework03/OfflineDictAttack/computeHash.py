import hashlib
import base64

# Now your task is to find the password that produces the following target_hash:
target_b64 = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8="
target_hash = base64.b64decode(target_b64)

with open("Dictionary.txt", "r") as f:
    for line in f.readlines():
        password = line.strip()
        # UTF-8 encode
        data = password.encode("utf-8")

        # SHA3-256
        digest = hashlib.sha3_256(data).digest()

        # Base64 (standard, with padding)
        b64 = base64.b64encode(digest).decode("ascii")

        if digest == target_hash:
            print("Password found: " + password)
            print("Base64: " + b64)

        if b64 == target_b64:
            print("Password found: " + password)
            print("Base64: " + b64)
