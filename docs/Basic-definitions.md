# Basic Definitions

The goal of this chapter is to define used functions related to cryptography and data manipulation. The definitions crafted in this chapter are then used in pseudo-codes in documentation. You can learn more about actual implementation of following functions in the "Implementation Notes" section.

## Cryptographic Functions

The following basic cryptography algorithms and parameters are used in the PowerAuth cryptography description:

### AES Symmetric Encryption

A symmetric key encryption algorithm. The AES algorithm is used with 256-bit keys.

- CTR mode is used as the encryption primitive inside AEAD and for unauthenticated key wrapping (UKE).
- GCM mode is used for local vault.

#### Encryption

Encrypt bytes using symmetric key with given initialization vector and `AES/CTR/NoPadding` transformation:

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key);
```

Encrypt bytes using symmetric key with given initialization vector and given cipher transformation:

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key, String transformation);
```

#### Decryption

Decrypt bytes using symmetric key with given initialization vector and `AES/CTR/NoPadding` transformation:

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key);
```

Decrypt bytes using symmetric key with given initialization vector and given cipher transformation:

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key, String transformation);
```

### Generic KDF

Keys are derived from an original secret using hierarchical string labels to guarantee that derived keys are never reused for different purposes.

The following method is used to derive a key from original secret value:

```java
SecretKey derivedKey = KDF.derive(SecretKey key, String label, byte[] diversifier, int outLength);
```

### Password KDF

An algorithm for key stretching, converts a short password into long key by performing KMAC-based derivation on the original data.

The following method will stretch the password using provided salt:

```java
SecretKey expandedKey = KDF.derivePassword(String password, byte[] salt);
```

### ECDSA Signatures

An algorithm for elliptic curve based signatures, uses SHA-384 hash algorithm and P-384 elliptic curve. It defines the following operations:

#### Data Signing

Compute signature of given data with a private key.

```java
byte[] signature = ECDSA.sign(byte[] data, PrivateKey privateKey);
```

#### Signature Verification

Verify the signature for given data using a given public key.

```java
boolean isValid = ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey);
```

### ML-DSA Signatures

Post-quantum signature algorithm MLDSA can be used for post-quantum signatures.

A ML-DSA key pair is generated with a specified variant of the algorithm: 
```java
KeyPair keyPair = MLDSA.generateKeyPair(String algorithm); // ML-DSA-65 or ML-DSA-87
```

A signature is created by signing the message raw bytes by private key from the ML-DSA keypair:
```java
byte[] signature = MLDSA.sign(PrivateKey privateKey, byte[] message);
```

A signature is verified for message raw bytes using public key from the ML-DSA keypair:
```java
boolean isValid = MLDSA.verify(PublicKey publicKey, byte[] message, byte[] signature);
```

### KEM / ECDH Key Agreement

KEM abstracts both ECDHE (P-384) and ML-KEM (ML-KEM-768 for `EC_P384_ML_L3`, ML-KEM-1024 for `EC_P384_ML_L5`). The concrete algorithm is selected based on the active security level.

Generate KEM key pair:

```java
KeyPair keyPair = KEM.generateKeyPair();
```

Encapsulation:

```java
Pair<SecretKey, byte[]> result = KEM.encapsulate(PublicKey publicKeyB);
```

Decapsulation:

```java
SecretKey secretKey = KEM.decapsulate(PrivateKey privateKeyA, byte[] ciphertext);
```

The resulting `SecretKey` represents the shared secret between parties.

### SharedSecret Interface

KEM is wrapped into a SharedSecret abstraction used by protocol flows.

Client derives shared secret from server response:

```java
SecretKey secretKey = SharedSecret.computeSharedSecret(
        SharedSecretClientContext context,
        SharedSecretResponse response
);
```

The interface internally uses `SharedSecretRequest`, `SharedSecretResponse`, and `SharedSecretClientContext` objects.

### UKE (Unauthenticated Key Encapsulation)

Primitive used for protecting factor-related keys (for example knowledge or biometry).

UKE provides confidentiality without authentication and intentionally avoids authenticated encryption to prevent offline brute-force oracles on low-entropy secrets (such as PINs).

Wrap key using provided KEK:

```java
byte[] wrapped = UKE.wrap(SecretKey key, SecretKey kek);
```

Unwrap key using provided KEK:

```java
SecretKey key = UKE.unwrap(byte[] wrapped, SecretKey kek);
```

### AEAD

Authenticated encryption used for End-To-End encryption and key protection.

A 12-byte unique nonce is used. For request/response flows, two independent nonces are used (one for request, one for response).

#### Seal

```java
byte[] ciphertext = AEAD.seal(
        SecretKey key,
        byte[] keyContext,
        byte[] nonce,
        byte[] associatedData,
        byte[] plaintext
);
```

The nonce is prepended to the ciphertext during encryption.

#### Open

```java
byte[] plaintext = AEAD.open(
        SecretKey key,
        byte[] keyContext,
        byte[] associatedData,
        byte[] ciphertext
);
```

The nonce is automatically extracted during decryption from ciphertext.

#### Extract Nonce

```java
byte[] nonce = AEAD.extractNonce(byte[] ciphertext);
```

AEAD internally derives encryption and authentication keys via KDF and authenticates data with KMAC-256.

### KDF

A key derivation function used to derive symmetric keys from a given master key.

A hierarchical KMAC-based derivation is used with string labels.

To obtain a key derived from a master key using a provided label:

```java
SecretKey derivedKey = KDF.derive(SecretKey masterKey, String label);
```

Example:

```java
SecretKey KDK_UTILITY = KDF.derive(masterKey, "util");
SecretKey KEY_STATUS = KDF.derive(KDK_UTILITY, "util/mac/status");
```

## Helper Functions

These functions are used in the pseudo-codes:

### Key Generators

#### Generate Random Key Pair

Generate a new EC key pair for the P-384 elliptic curve.

```java
KeyPair keyPair = ECKeyGenerator.randomKeyPair("P-384");
```

### Key Conversion Utilities

#### Convert Private Key to Bytes

Get bytes from the EC private key by encoding the D value (the number defining the EC private key).

```java
byte[] privateKeyBytes = KeyConversion.getBytes(PrivateKey privKey);
```

#### Convert Bytes to Private Key

Get EC key pair private key by decoding the bytes into the original D value (the number defining the EC private key).

```java
PrivateKey privateKey = KeyConversion.privateKeyFromBytes(byte[] privKeyBytes);
```

#### Convert Public Key to Bytes

Get bytes from the EC public key by encoding the Q value (the point defining the EC public key).

```java
byte[] publicKeyBytes = KeyConversion.getBytes(PublicKey pubKey);
```

#### Convert Bytes to Public Key

Get EC public key by decoding the bytes into the original Q value (the point defining the EC public key).

```java
PublicKey publicKey = KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes);
```

#### Convert Secret Key to Bytes

Get bytes from the symmetric key (using the `getEncoded` method).

```java
byte[] secretKeyBytes = KeyConversion.getBytes(SecretKey secretKey);
```

#### Convert Bytes to Secret Key

Create a symmetric key using provided bytes.

```java
SecretKey secretKey = KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes);
```

### Random Data Generators

#### Generate Random Data

Generate N random bytes using a secure random generator.

```java
byte[] randomBytes = Generator.randomBytes(int N);
```

#### Generate Random Base32 String

Generate string in Base32 encoding with N characters using a secure random generator.

```java
String randomBase32 = Generator.randomBase32String(int N);
```

#### Generate Random UUID

Generate a new UUID level 4 and return it in string representation.

```java
String uuid = Generator.randomUUID();
```

#### Generate Random Activation Code

Generate a new `ACTIVATION_CODE`. See [Activation Code](./Activation-Code.md) for more details.

```java
String code = Generator.randomActivationCode();
```

#### Build Activation Code With Random Bytes

Function return an activation code from given random data.

```java
String code = Generator.buildActivationCode(byte[10] randomBytes);
```

### MAC Functions

#### KMAC-256

Compute KMAC-256 signature for given message using provided symmetric key.

```java
byte[] signature = Mac.kmac256(SecretKey key, byte[] message, int outLength, String custom);
```

#### KMAC-256 Customization Strings

The following customization strings (`custom` parameter) are used across the protocol:

| Customization String | Used In                  | Description                                              |
|----------------------|--------------------------|----------------------------------------------------------|
| `PA4CODE`            | Authentication codes     | Authentication code component MAC calculation            |
| `PA4DIGEST`          | MAC tokens               | MAC token header digest                                 |
| `PA4DIGEST-DATA`     | Data digests             | Generic data digest MAC                                 |
| `PA4SH2`             | End-to-end encryption    | `SHARED_INFO_2` calculation in E2EE                     |
| `PA4MAC-QR`          | Activation (mobile SDK)  | Activation code QR signature MAC                        |
| `PA4MAC-STATUS`      | Activation status        | Activation status blob MAC                              |
| `PA4MAC-CTR`         | Authentication codes     | Counter data (`CTR_DATA`) hash MAC                      |
| `PA4KDF`             | Key derivation           | Generic KMAC-based key derivation (`KDF.derive`)        |
| `PA4PBKDF`           | Password key derivation  | Password-based key derivation (`KDF.derivePassword`)    |
| `PA4MAC-AEAD`        | AEAD encryption          | AEAD authentication tag calculation                     |

### Hashing Functions

#### SHA3

Compute SHA3 hash of a given input.

```java
byte[] hash = Hash.sha3_256(byte[] original);
```

```java
byte[] hash = Hash.sha3_384(byte[] original);
```

Note: SHA-384 (SHA-2) is used internally by ECDSA signatures for compatibility reasons.

### Password Hashing

#### Compute Password Hash

Compute Argon2 hash for given password. Hash is stored in Modular Crypt Format.

```java
String hash = PasswordHash.hash(byte[] password);
```

#### Verify Password Hash

Verify password against Argon2 hash stored in Modular Crypt Format.

```java
boolean matches = PasswordHash.verify(byte[] password, String hash);
```

### Utility Functions

#### Obtain Zero Byte Array

Generate buffer with N zero bytes.

```java
byte[] zeroBytes = ByteUtils.zeroBytes(int N);
```

#### Truncate Array

Get last N bytes of given byte array.

```java
byte[] truncatedBytes = ByteUtils.truncate(byte[] bytes, int N);
```

#### Get Numbers From Byte Array

Get integer value from big endian encoded byte array.

```java
int integer = ByteUtils.getInt(byte[4] bytes);
```

Get long value from big endian encoded byte array.

```java
long value = ByteUtils.getLong(byte[8] bytes);
```

#### Encode Primitive Types To Byte Array

Encode short value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(short n);
```

Encode int value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(int n);
```

Encode long value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(long n);
```

Encode string into sequence of bytes with UTF-8 encoding.

```java
byte[] encoded = ByteUtils.encode(String s);
```

#### Concatenate Data

Concatenate two or more byte arrays.

```java
byte[] ByteUtils.concat(byte[]... args) {
    byte[] result = new byte[0];
    for (byte[] component : args) {
        if (component != null && component.length > 0) {
          byte[] tmp = new byte[result.length + component.length];
          ByteUtils.copy(result, 0, tmp, 0, result.length);
          ByteUtils.copy(component, 0, tmp, result.length, component.length);
          result = tmp;
        }
    }
    return result;
}
```

Concatenate multiple byte array elements and prepend the length of each element.

```java
byte[] ByteUtils.concatWithSizes(byte[]... args) {
    byte[] result = new byte[0];
    for (byte[] component : args) {
        if (component != null) {
            result = ByteUtils.concat(result, ByteUtils.encode(component.length), component);
        } else {
            result = ByteUtils.concat(result, ByteUtils.encode((int)0));
        }
    }
    return result;
}
```

Concatenate multiple string elements and prepend the length of each element.

```java
byte[] ByteUtils.concatWithSizes(String... args) {
    byte[] result = new byte[0];
    for (String component : args) {
        if (component != null) {
            byte[] componentBytes = ByteUtils.encode(component);
            result = ByteUtils.concat(result, ByteUtils.encode(componentBytes.length), componentBytes);
        } else {
            result = ByteUtils.concat(result, ByteUtils.encode((int)0));
        }
    }
    return result;
}
```

#### Convert 32b Array to 16b

Converts 32b long byte array to 16b long array by xor-ing the first 16b with the second 16b, byte-by-byte.

```java
byte[] result = ByteUtils.convert32Bto16B(byte[] bytes32);
```

#### Obtain Sub-Array

Obtain subarray of a byte array, starting with index `startIndex` with a given length.

```java
byte[] result = ByteUtils.subarray(byte[] bytes, int startIndex, int length);
```

#### Copy Arrays

Copies `length` of bytes from the specified source array of bytes, beginning at the specified position, to the specified position of the destination array.

```java
ByteUtils.copy(byte[] source, int sourcePosition, byte[] destination, int destinationPosition, int length);
```

#### Current Time

Get UNIX timestamp in milliseconds, since 1.1.1970.

```java
long timestamp = Time.getTimestamp();
```
