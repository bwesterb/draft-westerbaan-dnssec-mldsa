---
title: "Module-Lattice Digital Signature Algorithm for DNSSEC"
abbrev: "ML-DSA for DNSSEC"
category: std

docname: draft-westerbaan-dnssec-mldsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Domain Name System Operations"
keyword:
 - DNSSEC
 - ML-DSA
 - post-quantum
 - FIPS 204
 - signatures
venue:
  group: "Domain Name System Operations"
  type: "Working Group"
  mail: "dnsop@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/dnsop/"
  github: "bwesterb/draft-westerbaan-dnssec-mldsa"
  latest: "https://bwesterb.github.io/draft-westerbaan-dnssec-mldsa/draft-westerbaan-dnssec-mldsa.html"

author:
 -
    ins: B.E. Westerbaan
    fullname: Bas Westerbaan
    organization: Cloudflare
    email: bas@cloudflare.com

normative:
  RFC2119:
  RFC4033:
  RFC4034:
  RFC4035:
  RFC8174:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    date: 2024-08
    seriesinfo:
      FIPS: PUB 204
    target: https://doi.org/10.6028/NIST.FIPS.204

informative:
  RFC6605:

...

--- abstract

This document describes how to specify Module-Lattice-Based Digital
Signature Algorithm (ML-DSA) keys and signatures in DNS Security
(DNSSEC).  It uses the ML-DSA-44 parameter set defined in FIPS 204.
ML-DSA-44 is believed to be secure even against adversaries in possession
of a cryptographically relevant quantum computer.

--- middle

# Introduction

DNSSEC, which is broadly defined in {{RFC4033}}, {{RFC4034}}, and
{{RFC4035}}, uses cryptographic keys and digital signatures to provide
authentication of DNS data.  Currently the most popular signature
algorithms in use are RSA and the NIST-specified elliptic curve
signature algorithm ECDSA {{RFC6605}}.

All currently specified algorithms rely for their security on the hardness of the
integer factorization problem or the (elliptic curve) discrete
logarithm problem.  A cryptographically relevant quantum computer when built
would be able to solve both of these problems efficiently, and
would therefore be able to forge DNSSEC signatures created with any of
these algorithms.

{{FIPS204}} specifies the Module-Lattice-Based Digital Signature
Algorithm (ML-DSA), a signature scheme whose security is based on the
hardness of lattice problems over module lattices.  ML-DSA is believed
to be secure even against adversaries in possession of a
cryptographically relevant quantum computer.  {{FIPS204}} defines three
parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

This document defines the use of DNSSEC's DS, DNSKEY, and RRSIG resource
records (RRs) with the ML-DSA-44 parameter set.  ML-DSA-44 targets NIST
security category 2, which equates to 160 bits of security classical
and post-quantum security. ML-DSA-44 has the smallest keys and signatures
of the three ML-DSA parameter sets, which makes it the most suitable
for use in the DNS.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# DNSKEY Resource Records

An ML-DSA-44 public key consists of a 1312-octet value as produced by
the key generation algorithm ML-DSA.KeyGen defined in Section 5.1 of
{{FIPS204}}.  It is encoded into the Public Key field of a DNSKEY
resource record as a simple bit string, using the byte encoding of the
public key described in Section 7.2 of {{FIPS204}}.

# RRSIG Resource Records

An ML-DSA-44 signature consists of a 2420-octet value as produced by the
signing algorithm ML-DSA.Sign defined in Section 5.2 of {{FIPS204}}.  It
is encoded into the Signature field of an RRSIG resource record as a
simple bit string, using the byte encoding of the signature described in
Section 7.2 of {{FIPS204}}.

Signatures are generated and verified using the "pure" ML-DSA variant
(i.e., not the pre-hash variant HashML-DSA) with an empty context string
(ctx of zero length), as described in Sections 5.2 and 5.3 of
{{FIPS204}}.  The message signed is the data to be signed as described
in Section 3.1.8.1 of {{RFC4034}}.

# Algorithm Number for DS, DNSKEY, and RRSIG Resource Records

The algorithm number associated with the use of ML-DSA-44 in DS, DNSKEY,
and RRSIG resource records is TBD1.  This registration is fully defined
in the IANA Considerations section.

# Examples

TODO: This section will contain worked examples of an ML-DSA-44 DNSKEY,
DS, and RRSIG record, following the format used in Section 6 of
{{RFC6605}}.  They are omitted from this revision because of the size of
ML-DSA-44 keys and signatures and are to be regenerated against the
final IANA algorithm number.

# Security Considerations

The security considerations of {{FIPS204}} apply.

In particular sections 3.4 and 3.6 of {{FIPS204}} discuss additional
considerations for implementing ML-DSA, including guidance on the
choice of hedged vs deterministic variants. These considerations
apply when ML-DSA is used for DNSSEC and especially during online signing.

# IANA Considerations

This document updates the IANA registry "Domain Name System Security
(DNSSEC) Algorithm Numbers".  The following entry is to be added to the
registry:

| Field                          | Value           |
|--------------------------------|-----------------|
| Number                         | TBD1            |
| Description                    | ML-DSA-44       |
| Mnemonic                       | MLDSA44         |
| Zone Signing                   | Y               |
| Trans. Sec.                    | \*              |
| Use for DNSSEC Signing         | MAY             |
| Use for DNSSEC Validation      | MAY             |
| Implement for DNSSEC Signing   | MAY             |
| Implement for DNSSEC Validation| MAY             |
| Reference                      | (this document) |
{: title="New DNSSEC Algorithm Number entry"}

\* There has been no determination of standardization of the use of this
algorithm with Transaction Security.

--- back

# Acknowledgments
{:numbered="false"}

Some of the material in this document is copied liberally from
{{RFC6605}} and RFC 8080 (EdDSA for DNSSEC).
