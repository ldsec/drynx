# Drynx

Drynx is a library for simulating a privacy-preserving and verifiable data sharing/querying tool. It offers a series of independent protocols that when combined offer a verifiably-secure and safe way to compute statistics and train basic machine learning models on distributed sensitive data (e.g., medical data).

Drynx is developed by lca1 (Laboratory for Communications and Applications in EPFL) in collaboration with DeDiS (Laboratory for Decentralized and Distributed Systems). It is build on the UnLynx library (https://github.com/lca1/unlynx) and does an intensive use of [Overlay-network (ONet) library](https://github.com/dedis/onet) and of the [Advanced Crypto (kyber) library](https://github.com/dedis/kyber).

# list of things that should be in the readMe:

1. -tags vartime for build and test
2. each encoding has a encode/decode function that is called by the DPs and queriers.


# TODO
1. key switching test
2. crypto_test
3. common_structs_test
4. remove drynx things from unlynx if any --> finish the crypto part, almost everything in drynx should leave and remain in unlynx
5. master travis (make local) should work completely

