# List of Used Algorithms

The following algorithms are used in the PowerAuth cryptography scheme.

## PowerAuth 3 Protocol

- Current protocol version: `3.3`

### Cryptographic Primitives

| Algorithm     | Impacts        | Note                                                                                                                                                                                                                                                      |
|---------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AES-128`     | mobile, server | Symmetric encryption with 128 bit keys. Used in `AES/CBC/PKCS7Padding` or `AES/CBC/NoPadding`, depending on use-case.                                                                                                                                     |
| `Argon2`      | server         | Iterative hash used for storing recovery PUK values associated with recovery codes (`argon2i`).                                                                                                                                                           |
| `CRC-16`      | mobile, server | Checksum algorithm, used to add a validation to the activation code (2 bytes out of 12 are allocated for checksum).                                                                                                                                       |
| `ECDH`        | mobile, server | Key agreement algorithm for ECC-based Diffie-Hellman, uses `secp256r1` curve.                                                                                                                                                                             |
| `ECDSA`       | mobile, server | Asymmetric signatures based on ECC, with `secp256r1` curve and `SHA256` hash function (`SHA256withECDSA`).                                                                                                                                                |
| `ECIES`       | mobile, server | Asymmetric encryption scheme based on ECC, with `secp256r1` and `X9.63` (`SHA256`) KDF function.                                                                                                                                                          |
| `HMAC-SHA256` | mobile, server | MAC algorithm with `SHA256` as underlying has function. Used in various situations across the protocol.                                                                                                                                                   |
| `HMAC-SHA512` | server         | MAC algorithm with `SHA256` as underlying has function. Currently only used when validating TOTP in proximity OTP feature.                                                                                                                                |
| `PBKDF2`      | mobile         | Derivation function, used with `HMAC-SHA1` algorithm (`PBKDF2WithHmacSHA1`) and 10 000 iterations. _Note: Used exclusively for deriving a symmetric encryption key from PIN code on a mobile device, and hence strength of the algorithm is unimportant._ |
| `SHA256`      | mobile, server | Hash function. Used in various situations across the protocol.                                                                                                                                                                                            |
| `X9.63`       | mobile, server | Key derivation function with `SHA256`. Used for deriving keys with random index.                                                                                                                                                                          |

### Algorithm Providers

- Server-Side: [Bouncy Castle](https://www.bouncycastle.org/)
- Client-Side: [OpenSSL](https://openssl-library.org/) (libCrypto)