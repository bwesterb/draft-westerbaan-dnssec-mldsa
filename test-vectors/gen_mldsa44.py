#!/usr/bin/env python3
"""Generate reproducible ML-DSA-44 DNSSEC test vectors for
draft-westerbaan-dnssec-mldsa.

This registers ML-DSA-44 into dnspython at runtime (no fork required) under
DNSSEC algorithm number 18 (a placeholder for the requested IANA assignment).

Keys are derived deterministically from a fixed 32-byte seed and signatures use
the FIPS 204 deterministic variant (rnd = 0^256), so the emitted vectors are
byte-for-byte reproducible.

Signing uses dilithium-py (pure-Python FIPS 204, deterministic mode).
Verification uses both dilithium-py and pyca/cryptography (OpenSSL), giving a
cross-implementation check.

Dependencies:
    pip install dnspython dilithium-py cryptography
"""

import base64
import textwrap

import dns.dnssec
import dns.dnssecalgs
import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
from dns.dnssecalgs.base import GenericPrivateKey, GenericPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

from cryptography.hazmat.primitives.asymmetric import mldsa
from dilithium_py.ml_dsa import ML_DSA_44

# DNSSEC algorithm number used for these vectors (placeholder for IANA TBD).
ALGORITHM = 18

# Fixed 32-byte key-generation seed (xi), so the key pair is reproducible.
SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

# Reuse the RFC 8080 example scaffolding.
ZONE = "example.com."
INCEPTION = 1438207200   # 20150729223000
EXPIRATION = 1440021600  # 20150819223000


class PublicMLDSA44(GenericPublicKey):
    """ML-DSA-44 public key, backed by pyca/cryptography (OpenSSL)."""

    algorithm = Algorithm.make(ALGORITHM)

    def __init__(self, key: mldsa.MLDSA44PublicKey) -> None:
        self.key = key

    def verify(self, signature: bytes, data: bytes) -> None:
        # Pure ML-DSA, empty context (context=None behaves as empty).
        self.key.verify(signature, data)

    def encode_key_bytes(self) -> bytes:
        return self.key.public_bytes_raw()  # 1312 octets

    @classmethod
    def from_dnskey(cls, key: DNSKEY) -> "PublicMLDSA44":
        cls._ensure_algorithm_key_combination(key)
        return cls(mldsa.MLDSA44PublicKey.from_public_bytes(key.key))

    @classmethod
    def from_pem(cls, public_pem: bytes) -> "PublicMLDSA44":
        raise NotImplementedError

    def to_pem(self) -> bytes:
        raise NotImplementedError


class PrivateMLDSA44(GenericPrivateKey):
    """ML-DSA-44 private key, backed by dilithium-py (deterministic FIPS 204)."""

    public_cls = PublicMLDSA44

    def __init__(self, key: tuple[bytes, bytes]) -> None:
        # key = (pk_bytes, sk_bytes)
        self.pk, self.sk = key

    def sign(
        self,
        data: bytes,
        verify: bool = False,
        deterministic: bool = True,
    ) -> bytes:
        # Always deterministic (rnd = 0^256), pure ML-DSA, empty context.
        signature = ML_DSA_44.sign(self.sk, data, ctx=b"", deterministic=True)
        if verify:
            self.public_key().verify(signature, data)
        return signature

    def public_key(self) -> PublicMLDSA44:
        return PublicMLDSA44(mldsa.MLDSA44PublicKey.from_public_bytes(self.pk))

    @classmethod
    def generate(cls) -> "PrivateMLDSA44":
        return cls(key=ML_DSA_44.keygen())

    @classmethod
    def from_seed(cls, seed: bytes) -> "PrivateMLDSA44":
        pk, sk = ML_DSA_44.key_derive(seed)
        return cls(key=(pk, sk))

    @classmethod
    def from_pem(cls, private_pem: bytes, password=None) -> "PrivateMLDSA44":
        raise NotImplementedError

    def to_pem(self, password=None) -> bytes:
        raise NotImplementedError


def wrap(b64: str) -> str:
    return "\n             ".join(textwrap.wrap(b64, 60))


def rdata_b64(rdata) -> str:
    # Presentation form of the record with the base64 blob wrapped.
    return rdata


def main() -> None:
    dns.dnssecalgs.register_algorithm_cls(ALGORITHM, PrivateMLDSA44)

    priv = PrivateMLDSA44.from_seed(SEED)
    pub = priv.public_key()

    # Cross-check: dilithium-py and cryptography agree on the public key.
    crypto_pk = (
        mldsa.MLDSA44PrivateKey.from_seed_bytes(SEED).public_key().public_bytes_raw()
    )
    assert crypto_pk == pub.encode_key_bytes(), "public key mismatch between libs"

    name = dns.name.from_text(ZONE)

    dnskey = dns.dnssec.make_dnskey(
        pub, algorithm=ALGORITHM, flags=Flag.ZONE | Flag.SEP
    )
    ds = dns.dnssec.make_ds(
        name, dnskey, "SHA256", policy=dns.dnssec.allow_all_policy
    )

    mx = dns.rrset.from_text(ZONE, 3600, "IN", "MX", "10 mail.example.com.")

    rrsig = dns.dnssec.sign(
        rrset=mx,
        private_key=priv,
        dnskey=dnskey,
        signer=name,
        inception=INCEPTION,
        expiration=EXPIRATION,
        verify=True,
        policy=dns.dnssec.allow_all_policy,
    )

    # Self-validate via dnspython (verification path uses cryptography).
    dnskey_rrset = dns.rrset.from_rdata(name, 3600, dnskey)
    rrsig_rrset = dns.rrset.from_rdata(name, 3600, rrsig)
    dns.dnssec.validate(
        mx,
        rrsig_rrset,
        {name: dnskey_rrset},
        now=INCEPTION,  # example timestamps are historical
        policy=dns.dnssec.allow_all_policy,
    )
    print("; validation OK (dnspython + cryptography)\n")

    key_tag = dns.dnssec.key_id(dnskey)

    print("Private-key-format: v1.3")
    print(f"Algorithm: {ALGORITHM} (MLDSA44)")
    print(f"PrivateKey: {base64.b64encode(SEED).decode()}\n")

    print(f"; key tag = {key_tag}")
    print(f"{ZONE} 3600 IN DNSKEY 257 3 {ALGORITHM} (")
    print(f"             {wrap(base64.b64encode(dnskey.key).decode())} )\n")

    print(f"{ZONE} 3600 IN DS {key_tag} {ALGORITHM} 2 (")
    print(f"             {wrap(ds.digest.hex())} )\n")

    print(f"{ZONE} 3600 IN MX 10 mail.example.com.\n")

    print(f"{ZONE} 3600 IN RRSIG MX {ALGORITHM} {rrsig.labels} {rrsig.original_ttl} (")
    print(f"             {EXPIRATION} {INCEPTION} {key_tag} {ZONE} (")
    print(f"             {wrap(base64.b64encode(rrsig.signature).decode())} )")


if __name__ == "__main__":
    main()
