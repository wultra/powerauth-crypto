# PowerAuth Cryptography Algorithm Overview

This document lists main cryptography algorithms used in the **PowerAuth** protocol, with emphasis on the shared secret computation, end-to-end encryption, and additional supporting cryptography algorithms.

---

## Shared Secret Algorithms

### EC_P256 (legacy)
- **Curve:** NIST P-256 (`secp256r1`).
- **Key Exchange:** ECDH.
- **Signatures:** ECDSA with **SHA-256**.
- **Status:** Supported for backward compatibility only.

---

### EC_P384
- **Curve:** NIST P-384 (`secp384r1`).
- **Key Exchange:** ECDH with SHA-3 based KDF.
- **Signatures:** ECDSA with **SHA-384**.
- **Status:** A suite of algorithms without post-quantum support, provided mainly for performance reasons.

---

### EC_P384_ML_L3 (Hybrid – PQC Level 3)
- **Components:**
    - **ECDH (P-384)**.
    - **ML-KEM-768**.
- **Mechanism:** Secrets derived independently, concatenated, and passed to KDF for shared key derivation.
- **Signatures:** ECDSA P-384 + SHA-384, ML-DSA-65, or hybrid.
- **Strength:** NIST PQC Level 3.

---

### EC_P384_ML_L5 (Hybrid – PQC Level 5)
- **Components:**
    - **ECDH (P-384)**.
    - **ML-KEM-1024**.
- **Mechanism:** Secrets derived independently, concatenated, and passed to KDF for shared key derivation.
- **Signatures:** ECDSA P-384 + SHA-384, ML-DSA-87, or hybrid.
- **Strength:** NIST PQC Level 5.

---

### ML_L3 (testing only)
- **Components:** ML-KEM-768 / ML-DSA-65.
- **Usage:** PQC only, no classical fallback.
- **Status:** Testing only.

---

### ML_L5 (testing only)
- **Components:** ML-KEM-1024 / ML-DSA-87.
- **Usage:** PQC only, no classical fallback.
- **Status:** Testing only.

---

## End-to-End Encryption Algorithms

### ECIES (legacy)
- **Encryption:** AES-128 in CTR mode.
- **MAC:** HMAC-SHA-256 (legacy) → KMAC-256 in later use.
- **Status:** Legacy scheme, replaced by AEAD, no crypto agility.

---

### AEAD (Authenticated Encryption with Associated Data)
- **Encryption:** AES-256 in CTR mode.
- **Authentication:** KMAC-256.
- **Role:** Standard scheme for end-to-end encryption shared by various shared secret algorithms.
- **Properties:** Confidentiality, integrity, authentication, replay protection, crypto agility.

---

## Supporting Cryptographic Algorithms 

### Authentication Codes
- **Legacy:** HMAC-SHA-256.
- **Current:** KMAC-256.
- **Factor keys:** Possession, Knowledge, Biometry (derived from activation secret).

---

### Hash Functions
- **Legacy:** SHA-256.
- **Current:** SHA-3 family (SHA3-256, SHAKE, KMAC), SHA-384 (only for P-384 ECDSA).