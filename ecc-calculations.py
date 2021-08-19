import Crypto.PublicKey.ECC
import Crypto.Hash.SHA256
import Crypto.Signature.DSS

import tinyec.registry
import tinyec.ec

import sys

# References -
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
# https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html
# https://github.com/alexmgr/tinyec
# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
# http://www.secg.org/sec1-v2.pdf (4.1.4 Verifying Operation)
# http://www.secg.org/sec2-v2.pdf (2.4.2 Recommended Parameters secp256r1)

key = Crypto.PublicKey.ECC.generate(curve='P-256')
print (f"key = {key}")

message = b'Message'
print (f"message = {message}")

digest = Crypto.Hash.SHA256.new(message)
print (f"digest = {digest.hexdigest()}")

signer = Crypto.Signature.DSS.new(key, 'fips-186-3')  # fips-186-3 - concatenated big-endian r,s
signature = signer.sign(digest)
print (f"signature = {signature.hex()}")

print ("=== Signature Verification Using PyCryptodome ===")

verifier = Crypto.Signature.DSS.new(key.public_key(), 'fips-186-3')
try:
    verifier.verify(digest, signature)
    print ("----> Signature matches.")
except ValueError:
    print ("----> Signature DOESN'T match!")
    sys.exit(1)


print ("=== Signature Verification Using ECC Calculations ===")

curve = tinyec.registry.get_curve("secp256r1")

r_bin = signature[0:32]
s_bin = signature[32:64]
print(f"r_bin = {r_bin.hex()}")
print(f"s_bin = {s_bin.hex()}")

if len(r_bin) + len(s_bin) != len(signature):
    print ("Signature is not of the expected size!")
    sys.exit(1)

r = int.from_bytes(r_bin, "big")
s = int.from_bytes(s_bin, "big")
print (f"r = {r}")
print (f"s = {s}")

# n and G taken from "2.4.2 Recommended Parameters secp256r1" in http://www.secg.org/sec2-v2.pdf -

n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
print (f"n = {n}")

G_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
G_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = tinyec.ec.Point(curve, G_x, G_y)
print (f"G = {G}")

# "ECDSA Verify Signature" from https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages -

s1 = pow(s, -1, n)
print (f"s1 = {s1}")

# R' = (h * s1) * G + (r * s1) * pubKey

h = int(digest.hexdigest(), 16)
print (f"h = {h}")
public_key = tinyec.ec.Point(curve, int(key.public_key().pointQ.x), int(key.public_key().pointQ.y))
print (f"public_key = {public_key}")

R_tag_a = (h * s1) * G
R_tag_b = (r * s1) * public_key
R_tag = R_tag_a + R_tag_b
print (f"R_tag = {R_tag}")

r_tag = R_tag.x
print (f"r_tag = {r_tag}")

if r_tag == r:
    print ("----> Signature matches.")
else:
    print ("----> Signature DOESN'T match!")
    sys.exit(1)