# End-to-End Encryption

## Standard ECIES Based End-to-End Encryption

PowerAuth supports a standard ECIES encryption (integrated encryption scheme that uses elliptic curve cryptography) with the P256r1 curve and standard X9.63 (SHA256) KDF function (that produces 48 bytes long key).

### Basic Definitions

Assume we have the following constants and variables defined in our scheme:

**Constants**

- `KEY_ENC_PUB` - Elliptic curve public key for ECDH key agreement.
- `KEY_ENC_PRIV` - Elliptic curve private key for ECDH key agreement.
- `VERSION` - String with the current version of the protocol.
- `SHARED_INFO_1` - is a pre-shared constant and is different for each endpoint (see [Pre-shared constants](#pre-shared-constants))
- `SHARED_INFO_2_BASE` - is a value calculated from parameters known for both parties.

**Variables**

- `PLAINTEXT` - Data to be encrypted.
- `ASSOCIATED_DATA` - Data transmitted as plaintext and included in MAC calculation.
- `TIMESTAMP` - Unix timestamp with milliseconds precision.
- `NONCE` - Unique nonce generated for each encryption.
- `EPH_KEYPAIR` - Ephemeral elliptic curve key-pair for ECDH key agreement.
- `KEY_EPH_PRIV` - Private part of `EPH_KEYPAIR`.
- `KEY_EPH_PUB` - Public part of `EPH_KEYPAIR`.
- `SHARED_INFO_2` - Input parameter to MAC calculation.

### Temporary Encryption Keys

To provide required cryptographic features, such as forward secrecy, encryption uses [temporary encryption keys](./Temporary-Encryption-Keys.md) since protocol version `3.3`. 

### Encryption Scope

PowerAuth protocol defines two basic usage scopes for ECIES encryption:

- In "application scope", ECIES encryption is available for a whole PowerAuth Client lifetime. In other words, your application can use this mode anytime in its lifetime.
- In "activation scope", ECIES encryption is available once the PowerAuth Client has a valid activation. In this mode, the encryptor is cryptographically bound to keys exchanged during the activation process.

#### Application Scope

ECIES in application scope has the following configuration of parameters:

- `KEY_ENC_PUB` is a [temporary key](./Temporary-Encryption-Keys.md) with given `TEMP_KEY_ID` identifier fetched from the server associated with a specific application version and signed with `KEY_SERVER_MASTER_PRIVATE` (to prove it was intended for the application scope).
- `SHARED_INFO_1` is a pre-shared constant and is different for each endpoint (see [Pre-shared constants](#pre-shared-constants))
- `SHARED_INFO_2_BASE` is calculated from `APPLICATION_SECRET`:
  ```java
  byte[] SHARED_INFO_2_BASE = Hash.sha256(APPLICATION_SECRET);
  ```
- `ASSOCIATED_DATA` is calculated as:
  ```java
  byte[] ASSOCIATED_DATA = ByteUtils.concatWithSizes(VERSION, APPLICATION_KEY, TEMP_KEY_ID);
  ```

<!-- begin box warning -->
Note that the `APPLICATION_SECRET` constant is in Base64 form, so we need to reinterpret that string as a sequence of ASCII encoded bytes.
<!-- end -->

#### Activation Scope

ECIES in activation scope has the following configuration of parameters:

- `KEY_ENC_PUB` is a [temporary key](./Temporary-Encryption-Keys.md) with given `TEMP_KEY_ID` identifier fetched from the server associated with a specific application version and activation, and signed with `KEY_SERVER_PRIVATE` (the key which is unique for each activation, to prove it was intended for the activations cope).
- `SHARED_INFO_1` is a pre-shared constant and is different for each endpoint (see [Pre-shared constants](#pre-shared-constants))
- `SHARED_INFO_2_BASE` is calculated from `APPLICATION_SECRET` and `KEY_TRANSPORT`:
  ```java
  byte[] SHARED_INFO_2_BASE = Mac.hmacSha256(KEY_TRANSPORT, APPLICATION_SECRET);
  ```
- `ASSOCIATED_DATA` is calculated as:
  ```java
  byte[] ASSOCIATED_DATA = ByteUtils.concatWithSizes(VERSION, APPLICATION_KEY, ACTIVATION_ID, TEMP_KEY_ID);
  ```

<!-- begin box warning -->
Note that the `APPLICATION_SECRET` constant is in Base64 form, so we need to reinterpret that string as a sequence of ASCII encoded bytes.
<!-- end -->

### ECIES Encryption

Assume we have a public key `KEY_ENC_PUB`, data `PLAINTEXT` to be encrypted, `ASSOCIATED_DATA` to be included in MAC calculation and a `SHARED_INFO_1` and `SHARED_INFO_2_BASE` constants (`byte[]`) as encryption parameters. ECIES encryption works in the following way:

1. Generate an ephemeral key pair:
    ```java
    EPH_KEYPAIR = (KEY_EPH_PRIV, KEY_EPH_PUB);
    ```
1. Generate `NONCE` and `TIMESTAMP`:
   ```java
   byte[] NONCE = Generator.randomBytes(16);
   long TIMESTAMP = Time.getTimestamp();
   ```
1. Prepare `SHARED_INFO_2` parameter for MAC calculation:
   ```java
   byte[] TIMESTAMP_BYTES = ByteUtils.encode(TIMESTAMP);
   byte[] SHARED_INFO_2 = ByteUtils.concatWithSizes(SHARED_INFO_2_BASE, NONCE, TIMESTAMP_BYTES, KEY_EPH_PUB, ASSOCIATED_DATA);
   ```
1. Derive base secret key (in this step, we do not trim the key to 16b only, we keep all 32b).
    ```java
    SecretKey KEY_BASE = ECDH.phase(KEY_EPH_PRIV, KEY_ENC_PUB);
    ```
1. Derive a secret key using X9.63 KDF function (using SHA256 internally). When calling the KDF, we use `VERSION`, `SHARED_INFO_1` together with `KEY_EPH_PUB` value (as raw `byte[]`) as an `info` parameter.
    ```java
    byte[] VERSION_BYTES = ByteUtils.encode(VERSION);
    byte[] INFO = Bytes.concat(VERSION_BYTES, SHARED_INFO_1, KEY_EPH_PUB);
    SecretKey KEY_SECRET = KDF_X9_63_SHA256.derive(KEY_BASE, INFO, 48);
    ```
1. Split the 48 bytes long `KEY_SECRET` to three 16B keys. The first part is used as an encryption key `KEY_ENC`. The second part is used as MAC key `KEY_MAC`. The final part is a key for IV derivation `KEY_IV`.
    ```java
    byte[] KEY_SECRET_BYTES = KeyConversion.getBytes(KEY_SECRET);
    SecretKey KEY_ENC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET, 0, 16));
    SecretKey KEY_MAC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET, 16, 16));
    SecretKey KEY_IV = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET, 32, 16));
    ```
1. Derive `IV` from `NONCE` and encrypt ata using AES.
    ```java
    byte[] IV = KDF_INTERNAL.derive(KEY_IV, NONCE);
    byte[] DATA_ENCRYPTED = AES.encrypt(PLAINTEXT, IV, KEY_ENC);
    ```
1. Compute the MAC of encrypted data, include `SHARED_INFO_2`.
    ```java
    byte[] DATA = Bytes.concat(DATA_ENCRYPTED, SHARED_INFO_2);
    byte[] MAC = Mac.hmacSha256(KEY_MAC, DATA);
    ```
1. Prepare ECIES payload.
    ```java
    EciesPayload payload = (DATA_ENCRYPTED, MAC, KEY_EPH_PUB, NONCE, TIMESTAMP);
    ```

If this is a response encryption, then we omit `KEY_EPH_PUB` and set it to `null` in steps 3. and 9. to make the response shorter. For example, `SHARED_INFO_2` is then calculated as:

```java
byte[] SHARED_INFO_2 = ByteUtils.concatWithSizes(SHARED_INFO_2_BASE, NONCE, TIMESTAMP_BYTES, null, ASSOCIATED_DATA);
```

### ECIES Decryption

Assume we have a private key `KEY_ENC_PRIV`, encrypted data as an instance of the ECIES payload `(DATA_ENCRYPTED, MAC, KEY_EPH_PUB, NONCE, TIMESTAMP)`, `ASSOCIATED_DATA` to be included in MAC calculation, and a `SHARED_INFO_1` and `SHARED_INFO_2_BASE` constants (`byte[]`) as decryption parameters. ECIES decryption works in a following way:

1. Prepare `SHARED_INFO_2` parameter for MAC calculation:
   ```java
   byte[] TIMESTAMP_BYTES = ByteUtils.encode(TIMESTAMP);
   byte[] SHARED_INFO_2 = ByteUtils.concatWithSizes(SHARED_INFO_2_BASE, NONCE, TIMESTAMP_BYTES, KEY_EPH_PUB, ASSOCIATED_DATA);
   ```
1. Derive base secret key from the private key and ephemeral public key from the ECIES payload (in this step, we do not trim the key to 16b only, we keep all 32b).
    ```java
    SecretKey KEY_BASE = ECDH.phase(KEY_ENC_PRIV, KEY_EPH_PUB);
    ```
1. Derive a secret key using X9.63 KDF function (using SHA256 internally). When calling the KDF, we use `VERSION`, `SHARED_INFO_1` together with `KEY_EPH_PUB` value (as raw `byte[]`) as an `info` parameter.
    ```java
    byte[] VERSION_BYTES = ByteUtils.encode(VERSION);
    byte[] INFO = Bytes.concat(VERSION_BYTES, SHARED_INFO_1, KEY_EPH_PUB);
    SecretKey KEY_SECRET = KDF_X9_63_SHA256.derive(KEY_BASE, INFO, 48);
    ```
1. Split the 48 bytes long `KEY_SECRET` to three 16B keys. The first part is used as an encryption key `KEY_ENC`. The second part is used as MAC key `KEY_MAC`. The final part is a key for IV derivation `KEY_IV`.
    ```java
    byte[] KEY_SECRET_BYTES = KeyConversion.getBytes(KEY_SECRET);
    SecretKey KEY_ENC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET_BYTES, 0, 16));
    SecretKey KEY_MAC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET_BYTES, 16, 16));
    SecretKey KEY_IV = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET_BYTES, 32, 16));
    ```
1. Validate the MAC value in payload against expected MAC value. Include `SHARED_INFO_2`. If the MAC values are different, terminate the decryption.
    ```java
    byte[] DATA = Bytes.concat(DATA_ENCRYPTED, SHARED_INFO_2);
    byte[] MAC_EXPECTED = Mac.hmacSha256(KEY_MAC, DATA);
    if (MAC_EXPECTED != MAC) {
        throw EciesException("Invalid MAC"); // terminate the validation with an error
    }
    ```
1. Decrypt the data using AES, with `IV` value derived from `NONCE`.
    ```java
    byte[] IV = KDF_INTERNAL.derive(KEY_IV, NONCE);
    byte[] PLAINTEXT = AES.decrypt(DATA_ENCRYPTED, IV, KEY_ENC);
    ```

If this is a response decryption, then we omit `KEY_EPH_PUB` and set it to `null` in step 1.

### Client-Server Implementation

Practical implementation of ECIES encryption in PowerAuth accounts for a typical request-response cycle, since encrypting RESTful API requests and responses is the most common use-case.

Client implementation creates an encryptor object that allows encrypting the request and decrypting the response. When encrypting the request, encryptor object accepts a `byte[]` and a [temporary public key](./Temporary-Encryption-Keys.md) . Then, it produces an instance of `EciesPayload` class. After it receives an encrypted response from the server, which is essentially another instance of `EciesPayload`, it is able to use the original encryption context (the shared encryption keys) to decrypt the response.

Server implementation creates a decryptor object that allows decrypting the original request data and encrypting the response. When server receives an encrypted request, essentially as an `EciesPayload` instance again, it uses a [temporary private key](./Temporary-Encryption-Keys.md) (looked up based on the temporary key ID) to decrypt the original bytes and uses the encryption context to encrypt a response to the client.

Since the client and server use the same encryption context, the ephemeral public key needs to be only sent with the request from the client. Response may only contain encrypted data and MAC value.

Each encryption context can only be used once, for a single request-response cycle.

### Structure of `EciesPayload`

The structure of the `EciesPayload` is following:

```java
public class EciesPayload {
    private byte[] encryptedData;
    private byte[] mac;
    private byte[] ephemeralPublicKey;
    private byte[] nonce;
}
```

#### Encrypted Request

The typical JSON encoded request is following:

```json
{
    "temporaryKeyId": "dc497e8a-8faa-44bc-a52a-20d8393005d2",
    "ephemeralPublicKey" : "A97NlW0JPLJfpG0AUvaRHRGSHh+quZu+u0c+yxsK7Xji",
    "encryptedData" : "qYLONkDWFpXefTKPbaKTA/PWdRYH5pk9uvGjUqSYbeK7Q0aOohK2MknTyviyNuSp",
    "mac" : "DNlZdsM1wgH8v2mAROjj3vmQu4DI4ZJnuTBzQMrHsew=",
    "nonce" : "ZQxUjy/hSRyJ3xBtqyXBeQ==",
    "timestamp" : 1691762307382
}
```

HTTP header example:

- Application scoped header:
  ```
  X-PowerAuth-Encryption: PowerAuth version="3.2",
      application_key="UNfS0VZX3JhbmRvbQ=="
  ```
- Activation scoped header:
  ```
  X-PowerAuth-Encryption: PowerAuth version="3.2",
      application_key="UNfS0VZX3JhbmRvbQ==",
      activation_id="c564e700-7e86-4a87-b6c8-a5a0cc89683f"
  ```
<!-- begin box warning -->
Note, that the header must not be added to the request, when activation scoped encryption is combined with [PowerAuth Signature](./Computing-and-Validating-Signatures.md).
<!-- end -->

#### Encrypted Response

The JSON response is similar, but without `ephemeralPublicKey` field:

```json
{
    "encryptedData" : "6gIBzx28iqPFxtI/UjSLnR8FoFB6xFyshfMsCzOShY/5FN6rcKLtkD2r9M0ihKKW2bviC4HmLUJWXZtDUog9LA==",
    "mac" : "/giQrgL3pX+ziYaWBgLCLUiPH/D5/f31A5lRxVA12sI=",
    "nonce" : "kpgl9EC9+4KiKsUFlwLidw==",
    "timestamp": 1691762307385
}
```

The response doesn't use HTTP headers.

### Pre-Shared Constants

PowerAuth protocol defines following `SHARED_INFO_1` (also called as `sh1` or `sharedInfo1`) constants for its own internal purposes:

| RESTful endpoint                      | ECIES scope  | `SHARED_INFO_1` value     |
| ------------------------------------- | ------------ |---------------------------|
| `/pa/v3/activation/create` (level 1)  | application  | `/pa/generic/application` |
| `/pa/v3/activation/create` (level 2)  | application  | `/pa/activation`          |
| `/pa/v3/upgrade`                      | activation   | `/pa/upgrade`             |
| `/pa/v3/vault/unlock`                 | activation   | `/pa/vault/unlock`        |
| `/pa/v3/token/create`                 | activation   | `/pa/token/create`        |

On top of that, following constants can be used for application-specific purposes:

| Purpose                                  | ECIES scope  | `SHARED_INFO_1` value     |
| ---------------------------------------- | ------------ |---------------------------|
| Generic encryptor for application scope  | application  | `/pa/generic/application` |
| Generic encryptor for activation scope   | activation   | `/pa/generic/activation`  |
