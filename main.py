# Copyright 2021 Nimrod Zimerman
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ecc_calculations

import Crypto.PublicKey.ECC
import Crypto.Hash.SHA256
import Crypto.Signature.DSS

import sys


def generate_keypair():
    key = Crypto.PublicKey.ECC.generate(curve=ecc_calculations.CURVE_NAME)
    return key


def generate_signature(keypair, message):
    print (f"keypair = {keypair}")
    print (f"message = {message}")

    digest = Crypto.Hash.SHA256.new(message)
    print (f"digest = {digest.hexdigest()}")

    signer = Crypto.Signature.DSS.new(keypair, ecc_calculations.CRYPTO_DOME_RANDOM_SIGNATURE_MODE, encoding="binary")
    signature = signer.sign(digest)
    print (f"signature = {signature.hex()}")

    return signature


def verify_signature_cryptodome(public_key, message, signature):

    digest = Crypto.Hash.SHA256.new(message)
    print (f"digest = {digest.hexdigest()}")

    verifier = Crypto.Signature.DSS.new(public_key, ecc_calculations.CRYPTO_DOME_RANDOM_SIGNATURE_MODE, encoding="binary")
    try:
        verifier.verify(digest, signature)
        return True
    except ValueError:
        return False


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

    valid = ecc_calculations.verify_signature_ecc_calcs(keypair.public_key(), message1, signature1)
    if valid:
        print("----> Signature matches.")
    else:
        print("----> Signature DOESN'T match!")
        sys.exit(1)


    print ("=== Public Key from Signature Using ECC Calculations ===")

    public_keys = ecc_calculations.public_keys_from_signature(message1, signature1)
    print("----> Valid public keys that can verify the signature -")
    for public_key in public_keys:
        print(public_key)
        if public_key == keypair.public_key():
            print ("(^^^ is identical to the original public key)")


    print ("=== Public Key from Multiple Signatures Using ECC Calculations ===")

    # Two signatures are enough to get a single valid public key.
    messages_and_signatures = [
        [ message1, signature1 ],
        [ message2, signature2 ],
        [ message3, signature3 ],
    ]
    public_keys = ecc_calculations.public_keys_from_multiple_signatures(messages_and_signatures)

    if len(public_keys) == 0:
        print ("No public keys identified matching all signatures.")
    else:
        print ("Public keys identified matching all signatures -")
        for public_key in public_keys:
            print (public_key)
            if public_key == keypair.public_key():
                print ("(^^^ is identical to the original public key)")


main()
