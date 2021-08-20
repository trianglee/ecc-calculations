# ecc-calculations

Reference code for performing some ECC calculations directly with ECC operations.

The reference code is for NIST P-256 (secp256r1) curve, but can be relatively easily applied to 
other curves.

A useful function performed by this reference code is deriving a public key from
an ECC signature. This is an interesting operation, not commonly supported by
standard libraries.

## Calculations

* **verify_signature_ecc_calcs(public_key, message, signature)** - Verify an ECC
  signature over a message, with the provided public key.
* **public_keys_from_signature(message, signature)** - Derive possible public keys
  that can correctly verify the ECC signature over a message (more than a single
  valid public key may be returned).
* **public_keys_from_multiple_signatures(messages_and_signatures)** - Derive a single
  public key that can correctly verify all the ECC signatures over the messages.

## Used Libraries

**[pycryptodome](https://github.com/Legrandin/pycryptodome/)**, 
**[tinyec](https://github.com/alexmgr/tinyec)** and 
**[nummaster](https://pypi.org/project/nummaster/)** are used for various primitives.
