# SCRAM (Salted Challenge Response Authentication Mechanism)

## Which parts of SCRAM provide “client authentication”?
To proof himself the client needs to show the server that he knows the password without directly sending it over the network.

1. Request a challenge from the server
2. Calculate the salted password (with the according amount of iterations)
3. 

## Which parts of SCRAM provide “server authentication”

## If we do not use TLS to protect SCRAM, then which parts may cause offline dictionary attacks?
Without TLS an attacker can see the salt and the amount of iterations which allows them to do precomputation attacks