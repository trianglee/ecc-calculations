import Crypto.PublicKey.ECC
import Crypto.Hash.SHA256
import Crypto.Signature.DSS

import tinyec.registry
import tinyec.ec

import nummaster.basic

import sys

# References -
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
# https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html
# https://github.com/alexmgr/tinyec
# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
# http://www.secg.org/sec1-v2.pdf (4.1.4 Verifying Operation)
# http://www.secg.org/sec2-v2.pdf (2.4.2 Recommended Parameters secp256r1)
# https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc


# NIST P-256 / secp256r1 curve parameters -
# (also available from "2.4.2 Recommended Parameters secp256r1" in http://www.secg.org/sec2-v2.pdf)

CURVE_NAME = "secp256r1"  # Also known as "NIST P-256"

curve = tinyec.registry.get_curve(CURVE_NAME)
curve_params = tinyec.registry.EC_CURVE_REGISTRY[CURVE_NAME]

p = curve_params["p"]
a = curve_params["a"]
b = curve_params["b"]
G = tinyec.ec.Point(curve, curve_params["g"][0], curve_params["g"][1])
n = curve_params["n"]

###

CRYPTO_DOME_RANDOM_SIGNATURE_MODE = "fips-186-3"  # Random signature generation

###


def generate_keypair():
    key = Crypto.PublicKey.ECC.generate(curve=CURVE_NAME)
    return key


def generate_signature(keypair, message):
    print (f"keypair = {keypair}")
    print (f"message = {message}")

    digest = Crypto.Hash.SHA256.new(message)
    print (f"digest = {digest.hexdigest()}")

    signer = Crypto.Signature.DSS.new(keypair, CRYPTO_DOME_RANDOM_SIGNATURE_MODE, encoding="binary")
    signature = signer.sign(digest)
    print (f"signature = {signature.hex()}")

    return signature


def verify_signature_cryptodome(public_key, message, signature):

    digest = Crypto.Hash.SHA256.new(message)
    print (f"digest = {digest.hexdigest()}")

    verifier = Crypto.Signature.DSS.new(public_key, CRYPTO_DOME_RANDOM_SIGNATURE_MODE, encoding="binary")
    try:
        verifier.verify(digest, signature)
        return True
    except ValueError:
        return False


def extract_r_s_from_signature(signature):

    # Each signature component size is exactly 32 bytes (256 bits).
    r_bin = signature[0:32]
    s_bin = signature[32:64]
    print(f"r_bin = {r_bin.hex()}")
    print(f"s_bin = {s_bin.hex()}")

    if (len(signature) != 64) or (len(r_bin) + len(s_bin) != len(signature)):
        print ("Signature is not of the expected size!")
        sys.exit(1)

    r = int.from_bytes(r_bin, "big")
    s = int.from_bytes(s_bin, "big")
    print (f"r = {r}")
    print (f"s = {s}")

    return (r,s)


def verify_signature_ecc_calcs(public_key, message, signature):

    (r,s) = extract_r_s_from_signature(signature)

    # "ECDSA Verify Signature" from https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages -
    # (and also "4.1.4 Verifying Operation" from http://www.secg.org/sec1-v2.pdf, with slightly different names)

    s1 = pow(s, -1, n)
    print (f"s1 = {s1}")

    # R' = (h * s1) * G + (r * s1) * pubKey

    digest = Crypto.Hash.SHA256.new(message)
    print (f"digest = {digest.hexdigest()}")

    h = int(digest.hexdigest(), 16)  # Called "e" in 4.1.4.
    print (f"h = {h}")
    public_key = tinyec.ec.Point(curve, int(public_key.pointQ.x), int(public_key.pointQ.y))
    print (f"public_key = {public_key}")

    R_tag_a = (h * s1) * G
    R_tag_b = (r * s1) * public_key
    R_tag = R_tag_a + R_tag_b
    print (f"R_tag = {R_tag}")

    r_tag = R_tag.x
    print (f"r_tag = {r_tag}")

    if r_tag == r:
        return True
    else:
        return False


def public_keys_from_signature(message, signature):

    # Taken from https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc, unused.
    # def uncompress_point(compressed_point, p, a, b):
    #     x, is_odd = compressed_point
    #     y = nummaster.basic.sqrtmod(pow(x, 3, p) + a * x + b, p)
    #     if bool(is_odd) == bool(y & 1):
    #         return (x, y)
    #     return (x, p - y)

    # Derive the y-component of a compressed point, given the x-component only, assuming the y-component is odd.
    def uncompress_point_odd(x, p, a, b):
        y = nummaster.basic.sqrtmod(pow(x, 3, p) + a * x + b, p)
        return y


    # "4.1.6 Public Key Recovery Operation" from http://www.secg.org/sec1-v2.pdf -

    (r,s) = extract_r_s_from_signature(signature)

    candidate_public_key_points = []

    for j in [0, 1]:  # "h" of the curve is 1.

        x = r + j * n
        print(f"x = {x}")
        try:
            y = uncompress_point_odd(x, p, a, b)
            print(f"y = {y}")
        except Exception:
            print("Decompressing point failed, trying next.")
            continue

        R = tinyec.ec.Point(curve, x, y)
        print(f"R = {R}")

        n_dot_R = n * R
        print(f"n*R = {n_dot_R}")
        if n_dot_R != tinyec.ec.Inf(curve):
            print("n*R isn't Inf, trying next.")
            continue

        digest = Crypto.Hash.SHA256.new(message)
        e = int(digest.hexdigest(), 16)
        for k in [1, -1]:  # Try both with a positive and a negative R.
            Q = pow(r, -1, n) * (s * (k * R) - e * G)
            print(f"Q = {Q}")

            candidate_public_key_points.append(Q)

    valid_public_keys = []
    for candidate_public_key_point in candidate_public_key_points:
        Crypto_candidate_public_key_point = Crypto.PublicKey.ECC.EccPoint(candidate_public_key_point.x,
                                                                          candidate_public_key_point.y, curve=CURVE_NAME)
        Crypto_candidate_public_key = Crypto.PublicKey.ECC.EccKey(point=Crypto_candidate_public_key_point, curve=CURVE_NAME)

        verifier = Crypto.Signature.DSS.new(Crypto_candidate_public_key, CRYPTO_DOME_RANDOM_SIGNATURE_MODE, encoding="binary")
        try:
            verifier.verify(digest, signature)
            # Signature matches, store the public key.
            valid_public_keys.append(Crypto_candidate_public_key)
        except ValueError:
            # Signature doesn't match, continue.
            continue

    return valid_public_keys


def public_keys_from_multiple_signatures(messages_and_signatures):

    intersecting_public_keys_pem = None

    for message_and_signature in messages_and_signatures:
        (message, signature) = message_and_signature

        public_keys = public_keys_from_signature(message, signature)

        # Convert public keys to PEM because EccKey isn't hashable, and cannot be used in a set.
        public_keys_pem = set([ public_key.export_key(format="PEM") for public_key in public_keys ])

        if intersecting_public_keys_pem is None:
            intersecting_public_keys_pem = public_keys_pem
        else:
            intersecting_public_keys_pem = intersecting_public_keys_pem.intersection(public_keys_pem)

    # Convert PEM public keys back to EccKey.
    intersecting_public_keys = [ Crypto.PublicKey.ECC.import_key(public_key_pem) for public_key_pem in intersecting_public_keys_pem ]

    return list(intersecting_public_keys)


def main():

    keypair = generate_keypair()

    message1 = b'Message 1'
    message2 = b'Message 2'
    message3 = b'Message 3'

    signature1 = generate_signature(keypair, message1)
    signature2 = generate_signature(keypair, message2)
    signature3 = generate_signature(keypair, message3)


    print ("=== Signature Verification Using PyCryptodome ===")

    valid = verify_signature_cryptodome(keypair.public_key(), message1, signature1)
    if valid:
        print("----> Signature matches.")
    else:
        print("----> Signature DOESN'T match!")
        sys.exit(1)


    print ("=== Signature Verification Using ECC Calculations ===")

    valid = verify_signature_ecc_calcs(keypair.public_key(), message1, signature1)
    if valid:
        print("----> Signature matches.")
    else:
        print("----> Signature DOESN'T match!")
        sys.exit(1)


    print ("=== Public Key from Signature Using ECC Calculations ===")

    public_keys = public_keys_from_signature(message1, signature1)
    print("----> Valid public keys that can verify the signature -")
    for public_key in public_keys:
        print(public_key)
        if public_key == keypair.public_key():
            print ("(^^^ is identical to the original public key)")


    print ("=== Public Key from Multiple Signatures Using ECC Calculations ===")

    messages_and_signatures = [
        [ message1, signature1 ],
        [ message2, signature2 ],
        [ message3, signature3 ],
    ]
    public_keys = public_keys_from_multiple_signatures(messages_and_signatures)

    if len(public_keys) == 0:
        print ("No public keys identified matching all signatures.")
    else:
        print ("Public keys identified matching all signatures -")
        for public_key in public_keys:
            print (public_key)
            if public_key == keypair.public_key():
                print ("(^^^ is identical to the original public key)")


main()
