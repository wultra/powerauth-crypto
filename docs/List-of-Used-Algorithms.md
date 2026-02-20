# List of Used Algorithms

The following algorithms are used in the PowerAuth cryptography scheme.

## Cryptographic Algorithm Suite IDs (4.0)

The **Cryptographic Algorithm Suite** is a collection of specific cryptographic algorithms used throughout the various areas of the PowerAuth protocol. The main components are algorithms for key agreement and algorithms for digital signatures.

| Suite ID        | Status  | Description                                                                                                                                                |
|-----------------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `EC_P384_ML_L3` | Current | **Hybrid PQC Level 3**<ul><li>Key agreement: `ECDH (P-384) + ML-KEM-768`. Secrets concatenated before KDF.</li><li>Digital signatures: `ECDSA (P-384, SHA-384) + ML-DSA-65`</li></ul>Targets NIST PQC Level 3. |
| `EC_P384_ML_L5` | Current | **Hybrid PQC Level 5**<ul><li>Key agreement: `ECDH (P-384) + ML-KEM-1024`. Secrets concatenated before KDF.</li><li>Digital signatures: `ECDSA (P-384, SHA-384) + ML-DSA-87`</li></ul>Targets NIST PQC Level 5. |
| `EC_P384`       | Current | **Curve: NIST P-384 (`secp384r1`)**<ul><li>Key agreement: `ECDH (P-384, SHA-3 KDF)`</li><li>Digital signatures: `ECDSA (P-384, SHA-384)`</li></ul>No PQC component. |
| `ML_L3`         | Testing | **PQC-only Level 3**<ul><li>Key agreement: `ML-KEM-768`</li><li>Digital signatures: `ML-DSA-65`</li></ul>Targets NIST PQC Level 3. |
| `ML_L5`         | Testing | **PQC-only Level 5**<ul><li>Key agreement: `ML-KEM-1024`</li><li>Digital signatures: `ML-DSA-87`</li></ul>Targets NIST PQC Level 5. |
| `EC_P256`       | Legacy  | **Curve: NIST P-256 (`secp256r1`)**<ul><li>Key agreement: `ECDH (P-256)`</li><li>Digital signatures: `ECDSA (P-256, SHA-256)`</li></ul>Retained for 3.x compatibility only. |

## End‑to‑End Encryption

### AEAD (Authenticated Encryption with Associated Data)
- **Encryption:** `AES‑256` in CTR mode.
- **Authentication:** `KMAC‑256`.
- **Properties:** Confidentiality, integrity, authentication, replay protection, and crypto agility. Used uniformly across shared‑secret suites above, except legacy suite `EC_P256`, which uses the `ECIES` scheme.

## Algorithm Selection & Negotiation
- Clients and servers negotiate the shared secret suite (e.g., `EC_P384`, `EC_P384_ML_L3`, `EC_P384_ML_L5`) during capability exchange.
- `AEAD` with `AES‑256‑CTR + KMAC‑256` is used across 4.0 suites to streamline implementation.
- Hybrid suites concatenate classical and PQC secrets before KDF.

## List of Used Algorithms

### PowerAuth Protocol 4.x — **Current**

**Current protocol version:** `4.0`

#### Cryptographic Primitives

| Algorithm            | Impacts        | Note                                                                                                                                                                        |
|----------------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AEAD`               | mobile, server | Symmetric encryption in AEAD scheme using AES with 256 bit keys. CTR mode is used for encryption, integrity guaranteed via KMAC‑256.                                        |
| `KMAC-256`           | mobile, server | Message authentication and AEAD tag, also used in KDF constructions and factor keys: Possession, Knowledge, Biometry. On mobile, KMAC-256 is used for PIN-to-ke derivation. |
| `ECDH P-384`         | mobile, server | Key agreement for classical part of hybrid and for EC_P384 suite on curve `secp384r1`.                                                                                      |
| `ECDSA P-384`        | mobile, server | Asymmetric signatures based on ECDSA with SHA‑384 on curve `secp384r1`.                                                                                                     |
| `ML-KEM-768/1024`    | mobile, server | PQC key encapsulation used in Level‑3/Level‑5 hybrid and PQC‑only suites.                                                                                                   |
| `ML-DSA-65/87`       | mobile, server | Asymmetric signatures based on the ML-DSA PQC signature scheme.                                                                                                             |
| `SHA3-256`           | mobile, server | Hash function based on Keccak, used in various situations across the protocol.                                                                                              |
| `CRC-16`             | mobile, server | Checksum for activation code validation (2 bytes of 12).                                                                                                                    |

### PowerAuth Protocol 3.x — **Legacy**

**Latest 3.x protocol version:** `3.3`

#### Cryptographic Primitives

| Algorithm     | Impacts        | Note                                                                                                                                                                                                                                                      |
|---------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AES-128`     | mobile, server | Symmetric encryption with 128 bit keys. Used in `AES/CBC/PKCS7Padding` or `AES/CBC/NoPadding`, depending on use-case.                                                                                                                                     |
| `CRC-16`      | mobile, server | Checksum algorithm, used to add a validation to the activation code (2 bytes out of 12 are allocated for checksum).                                                                                                                                       |
| `ECDH`        | mobile, server | Key agreement algorithm for ECC-based Diffie-Hellman, uses `secp256r1` curve.                                                                                                                                                                             |
| `ECDSA`       | mobile, server | Asymmetric signatures based on ECC, with `secp256r1` curve and `SHA256` hash function (`SHA256withECDSA`).                                                                                                                                                |
| `ECIES`       | mobile, server | Asymmetric encryption scheme based on ECC, with `secp256r1` and `X9.63` (`SHA256`) KDF function.                                                                                                                                                          |
| `HMAC-SHA256` | mobile, server | MAC algorithm with `SHA256` as underlying has function. Used in various situations across the protocol.                                                                                                                                                   |
| `HMAC-SHA512` | server         | MAC algorithm with `SHA512` as underlying has function. Currently only used when validating TOTP in proximity OTP feature.                                                                                                                                |
| `PBKDF2`      | mobile         | Derivation function, used with `HMAC-SHA1` algorithm (`PBKDF2WithHmacSHA1`) and 10 000 iterations. _Note: Used exclusively for deriving a symmetric encryption key from PIN code on a mobile device, and hence strength of the algorithm is unimportant._ |
| `SHA256`      | mobile, server | Hash function. Used in various situations across the protocol.                                                                                                                                                                                            |
| `X9.63`       | mobile, server | Key derivation function with `SHA256`. Used for deriving keys with random index.                                                                                                                                                                          |

#### Algorithm Providers
- **Server‑Side:** [Bouncy Castle](https://www.bouncycastle.org/)
- **Client‑Side:** [OpenSSL](https://openssl-library.org/) (libCrypto)
