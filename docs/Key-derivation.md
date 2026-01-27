# Key Derivation

As an outcome of the [Activation](./Activation.md) process, a single long‑term shared secret `KEY_ACTIVATION_SECRET` is established between the PowerAuth Client and PowerAuth Server.

PowerAuth uses the concept of derived keys. Each derived key is computed using the KDF algorithm with string labels:

``` java
SecretKey KEY_DERIVED = KDF.derive(SOURCE_KEY, "label/path");
```

The PowerAuth Client stores only derived keys and server public keys. The client must not store `KEY_ACTIVATION_SECRET` or `KEY_DEVICE_PRIVATE` in plaintext. The `KEY_DEVICE_PRIVATE` is stored  encrypted in the secure vault (see below). As a result, storing `KEY_ACTIVATION_SECRET` locally is not required.

Each key has exactly one purpose and all domains (authentication, encryption, vault, utilities) are strictly separated
via dedicated KDKs.

Depending on context, the term shared secret refers either to `KEY_ACTIVATION_SECRET` (long-term) or `KEY_TEMPORARY_SHARED_SECRET` (short-term).

## Authentication Factor Keys

All factor keys are derived from an intermediate key:

``` java
SecretKey KDK_AUTHENTICATION_CODE = KDF.derive(KEY_ACTIVATION_SECRET, "auth");
```

### Key Related to Possession Factor

``` java
SecretKey KEY_AUTHENTICATION_CODE_POSSESSION = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/possession");
```

This key is stored on the device using unauthenticated key encryption  and protected with a device‑specific key:

``` java
SecretKey DEVICE_KEY = Hash.sha3_256("device-specific-data");
SecretKey KEK_AUTHENTICATION_CODE_POSSESSION = KDF.derive(DEVICE_KEY, "enc/kek-possession");
```

The concrete method for obtaining device‑specific data is platform dependent and must follow platform best practices.

### Key Related to Knowledge Factor

``` java
SecretKey KEY_AUTHENTICATION_CODE_KNOWLEDGE = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/knowledge");
```

This key is stored encrypted using a key derived from a password or PIN code using the Password-based KDF.

The knowledge factor key may change over time (for example after password change). The server maintains current and next versions of this key.

Because unauthenticated encryption is used, decryption with an incorrect PIN produces random key material. This is intentional: verification always happens on the server side.

### Key Related to Biometric Factor

``` java
SecretKey KEY_AUTHENTICATION_CODE_BIOMETRY = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/biometry");
```

This key exists only if biometry is enabled. It is stored using platform  biometric storage (for example Secure Enclave on iOS or StrongBox on Android) and protected with a platform‑specific KEK.

If the platform provides only 128‑bit KEK, then the key is expanded as:

``` java
SecretKey KEK_AUTHENTICATION_CODE_BIOMETRY_256 = KDF.derive(KEK_AUTHENTICATION_CODE_BIOMETRY_128, "other/expand-biometry-key");
```

Similarly to the knowledge factor, the biometry factor key is dynamic and may be replaced during biometry add / remove operations.

## Encryption and Utility Keys

Encryption-related keys are derived from:

``` java
SecretKey KDK_ENCRYPTION = KDF.derive(KEY_ACTIVATION_SECRET, "enc");
```

Local persistent data (such as device and server public keys, and utility KDKs) is protected with:

``` java
SecretKey KEY_LOCAL_DATA = KDF.derive(DEVICE_KEY, "enc/local");
```

Utility keys are derived from:

``` java
SecretKey KDK_UTILITY = KDF.derive(KEY_ACTIVATION_SECRET, "util");
```

This domain is used for protocol-support purposes, including:
- MAC of hash-based counter (`util/mac/ctr-data`)
- MAC of activation status (`util/mac/status`)
- Signing temporary-key requests
  - `util/mac/get-app-temp-key` (derived from `APP_SECRET`, application scope)
  - `util/mac/get-act-temp-key` (derived from `KDK_UTILITY`, activation scope)
- MAC of personalized data (`util/mac/personalized-data`)
- SHARED_INFO_2 derivation for end-to-end encryption(`util/key-e2ee-sh2`)
- Application-specific utilities (`util/app`)

## Temporary Shared Secret

The protocol uses temporary shared secrets for end‑to‑end encryption.

For each encrypted session, the client and server establish:

``` java
SecretKey KEY_TEMPORARY_SHARED_SECRET;
```

This key is short‑lived and is derived via a dedicated shared‑secret exchange. It is then expanded into AEAD encryption keys for protecting request and response payloads. Temporary secrets are never persisted long‑term on the client.

## Secure Vault

### Vault Encryption Key

Local vault protection is derived directly from `KEY_ACTIVATION_SECRET`.

``` java
SecretKey KDK_VAULT = KDF.derive(KEY_ACTIVATION_SECRET, "vault");

SecretKey KEK_DEVICE_PRIVATE = KDF.derive(KDK_VAULT, "vault/kek-device-private");
```

The original device private key is stored encrypted using AEAD. The vault encryption key is never stored directly. It is always re‑derived from `KEY_ACTIVATION_SECRET` when needed.

Additional vault derivation keys exist for application‑specific secrets that are released only after successful two‑factor authentication:

``` java
SecretKey KDK_APP_VAULT_KNOWLEDGE = KDF.derive(KDK_VAULT, "vault/kdk-app-vault-knowledge");

SecretKey KDK_APP_VAULT_2FA = KDF.derive(KDK_VAULT, "vault/kdk-app-vault-2fa");
```

These keys allow applications to protect additional sensitive material that becomes available only after successful authentication.

