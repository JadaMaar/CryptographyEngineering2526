# SCRAM (Salted Challenge Response Authentication Mechanism)

## Which parts of SCRAM provide “client authentication”?
To proof himself the client needs to show the server that he knows the password without directly sending it over the network.

1. The client computes a proof using a salted and hashed version of the password, along with
exchanged nonces and protocol messages. This proof demonstrates knowledge of the correct password without
revealing it.
2. The server stores a salted and hashed version of the user's password.
During authentication, the client derives keys from the password and salt to generate the proof.
3. Both client and server contribute random nonces, ensuring freshness of each authentication
session and preventing replay attacks.

## Which parts of SCRAM provide “server authentication”
Server authentication is achieved through the following mechanisms:

1. Server Signature: After verifying the client proof, the server sends a server signature derived from the shared
authentication information. The client verifies this signature to confirm the server's legitimacy.
2. Shared Authentication Messages: Both parties use the same exchanged messages to compute cryptographic
values. A valid server signature confirms that the server possesses the correct stored keys.


## If we do not use TLS to protect SCRAM, then which parts may cause offline dictionary attacks?
Without TLS an attacker can see the salt and the amount of iterations which allows them to do precomputation attacks

1. An attacker who intercepts the client-first message, server-first message,
and client-final message can obtain the salt, iteration count, and nonces.
2. The client proof is transmitted over the network. Without encryption, an attacker can
record this value and attempt to guess the password offline.
3. These values are public in SCRAM. An attacker can use them together with the
captured proof to compute candidate hashes from a dictionary of possible passwords.