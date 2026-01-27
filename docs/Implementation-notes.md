# Implementation Notes

Following implementation notes use simplified Java code with definitions from the "Definitions" section or a simple pseudo-code to get the point across quicker.

## Used Cryptography

PowerAuth protocol uses a hybrid cryptographic design:

- **ECC (P-384)** for ECDSA signatures and ECDH key agreement
- **ML-DSA (65 / 87)** for post-quantum hybrid signatures
- **Hybrid shared secret establishment** (HPKE + PQC KEM)
- **AEAD** construction for end-to-end encryption

Application-scope and activation-scope responses are signed using ECDSA P-384 and optionally ML-DSA (hybrid mode). Long-term activation secrets and short-term temporary secrets are derived from hybrid key exchange.

Authentication codes are computed from derived factor keys (possession / knowledge / biometry) and protocol data. Verification always happens on the server side.

## Algorithm Suites and Shared Secret Derivation

PowerAuth protocol supports multiple **algorithm suites** that define:

- Which asymmetric keys are exchanged
- Which KEMs participate in shared secret establishment
- Whether post-quantum protection is enabled
- Which signing keys are used for responses

The selected algorithm suite directly impacts how `KEY_ACTIVATION_SECRET` and `KEY_TEMPORARY_SHARED_SECRET` are derived.

Supported suites:

- **EC_P384**
    - Classical mode
    - Uses ECDH P-384 (HPKE DHKEM)
    - Shared secret is derived from a single ECDH-based DHKEM

- **EC_P384_ML_L3**
    - Hybrid post-quantum mode (Level 3)
    - Uses ECDH P-384 (HPKE DHKEM) + ML-KEM-768
    - Shared secret is derived from *both* ECC and PQC secrets

- **EC_P384_ML_L5**
    - Hybrid post-quantum mode (Level 5)
    - Uses ECDH P-384 (HPKE DHKEM) + ML-KEM-1024
    - Shared secret is derived from *both* ECC and PQC secrets

For hybrid suites, multiple KEM secrets are concatenated and passed into a KMAC-based KDF (NIST SP 800‑56C style) together with protocol version and algorithm label:

```
LABEL = "shared-secret/<ALGORITHM>"
```

The resulting 256‑bit output becomes:

- `KEY_ACTIVATION_SECRET` during activation
- `KEY_TEMPORARY_SHARED_SECRET` during temporary key establishment

Both client and server perform identical derivation. Neither side ever stores intermediate KEM secrets.

Once an activation is established, the selected suite becomes fixed for that activation. Temporary keys must use one of the algorithms currently supported by the application, but activation requests continue to rely on the originally negotiated suite.

## Key Derivation Functions

KDF (Key Derivation Function) is used to derive domain-separated keys from shared secrets.

PowerAuth uses label-based KDF instead of numeric indexes. Each key is derived using a string label such as:

- `auth/*` – authentication domain
- `enc/*` – encryption domain
- `vault/*` – secure vault
- `util/*` – protocol utilities
- `other/*` – auxiliary derivations

Example:

```java
SecretKey KEY = KDF.derive(SOURCE_KEY, "auth/possession");
```

In addition:

- **PBKDF2** is used only for deriving device encryption keys from user PIN / password (knowledge factor).

## Activation ID

The `ACTIVATION_ID` must be in principle long, universally unique, random and with a temporary validity. UUID level 4 is therefore the selected format of this ID.

```sql
DO {
    ACTIVATION_ID = UUID_GEN()
    COUNT = SELECT COUNT(*) FROM ACTIVATION WHERE ACTIVATION.ID = ACTIVATION_ID
} WHILE (COUNT > 0);
```

Example of activation ID:

```
c564e700-7e86-4a87-b6c8-a5a0cc89683f
```

<!-- begin box warning -->
A single UUID for an activation in `CREATED` or `PENDING_COMMIT` state must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most).
<!-- end -->

## Activation Code

The `ACTIVATION_CODE` is a Base32 string of 4 x 5 characters. The code is randomly generated and contains CRC-16 checksum which can detect a few typing errors in the code. For more details, check a [dedicated document](./Activation-Code.md) about the code construction and validation.

A single `ACTIVATION_CODE` must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most). Also, the activation code can be used only once. The moment a client application sends and receives the encrypted public keys, it must be marked as already used.

```sql
DO {
    ACTIVATION_CODE = Generator.randomActivationCode()
    COUNT = SELECT COUNT(*) FROM ACTIVATION WHERE (ACTIVATION.STATE = 'CREATED' OR ACTIVATION.STATE = 'PENDING_COMMIT') AND ACTIVATION.CODE = ACTIVATION_CODE
} WHILE (COUNT > 0);
```

Example of activation code:

```
MMMMM-MMMMM-MMMMM-MUTOA
```

## Application Key and Application Secret

In order to explicitly bind a client application with the cryptography, an application key and application secret are introduced. Both values follow the same format - 16B encoded as Base64, application ID must be unique.

Both identifiers are embedded in the PowerAuth Client application (for example, defined as constants in the source code).

Application key is sent with every PowerAuth Authentication as `pa_application_key`.

Application secret enters the authentication algorithm in final MAC computation and hence it is a part of the PowerAuth authentication (sent implicitly in `pa_auth_code`). It never travels from the application in plain text format.

## Entering Values in Client Application

Entering `ACTIVATION_CODE` and `ACTIVATION_SIGNATURE` can be expedited for example by using QR code for the storage. PowerAuth defines using following format of information:

```
${ACTIVATION_CODE}#${ACTIVATION_SIGNATURE}
```

Example concatenated string:

```
MMMMM-MMMMM-MMMMM-MUTOA#1234567890
```

<!-- begin box info -->
You can also check [Activation Code](./Activation-Code.md) document to get a more details about an activation code.
<!-- end -->

## Generating Key Pairs

The device and server ECC keys are generated using ECDSA / ECDH with **P-384** curve:

```java
public KeyPair generateKeyPair() {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
    keyPairGenerator.initialize(new ECGenParameterSpec("secp384r1"));
    return keyPairGenerator.generateKeyPair();
}
```

Generating ML-DSA signing keys (used for hybrid signatures):
```java
public KeyPair generateMlDsaKeyPair(MLDSAParameterSpec dsaParameterSpec) {
    // variant: "ML-DSA-65" or "ML-DSA-87"
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", "BC");
    keyPairGenerator.initialize(dsaParameterSpec);
    return keyPairGenerator.generateKeyPair();
}
```

Generating ML-KEM keys (used for hybrid shared secret derivation):
```java
public KeyPair generateMlKemKeyPair(MLKEMParameterSpec kemParameterSpec) {
    // variant: "ML-KEM-768" or "ML-KEM-1024"
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", "BC");
    keyPairGenerator.initialize(kemParameterSpec);
    return keyPairGenerator.generateKeyPair();
}
```

## Secure Network Communication

All communication should be carried over a properly secured channel, such as HTTPS with correct server configuration and certificate issued with a trusted certificate authority. Client may implement certificate pinning to achieve better transport level security.

## Lifecycle of the "Master Server Key Pair"

Since the same master server key is used for all activations, the "latent private key fingerprints" may accumulate over the time. While these hints are impractical from the attacker's perspective, it is recommended to renew the key after certain time period. Usually, this also requires timely update of the clients that bundle the master server public key.

## Signing Data Using Master Server Private Key

The master server key pair is generated using the same algorithm as a normal key pair, see above (with P-384 curve).

In order to generate the signature for given bytes (obtained from string by conversion using UTF-8 encoding), following code is used:

```java
public byte[] signatureForBytes(byte[] bytes, PrivateKey privateKey) {
    Signature ecdsaSign = Signature.getInstance("SHA384withECDSA", "BC"); // we assume BouncyCastle provider
    ecdsaSign.initSign(privateKey);
    ecdsaSign.update(bytes);
    byte[] signature = ecdsaSign.sign();
    return signature;
}
```

To verify the signature, following code is used:

```java
public boolean isSignatureCorrectForBytes(byte[] bytes, byte[] signature, PublicKey publicKey) {
    Signature ecdsaVerify = Signature.getInstance("SHA384withECDSA", "BC"); // we assume BouncyCastle provider
    ecdsaVerify.initVerify(publicKey);
    ecdsaVerify.update(bytes);
    boolean result = ecdsaVerify.verify(signature);
    return result;
}
```

In hybrid mode, signatures may additionally include ML-DSA:

- `MLDSA.sign(PrivateKey, byte[])`
- `MLDSA.verify(PublicKey, byte[], signature)`

Supported algorithms:
- `ML-DSA-65`
- `ML-DSA-87`
