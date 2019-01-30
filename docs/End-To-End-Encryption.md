# End-to-End Encryption

## Standard ECIES Based End-to-End Encryption

PowerAuth supports a standard ECIES encryption (integrated encryption scheme that uses elliptic curve cryptography) with the standard X9.63 (SHA256) KDF function (that produces 32b long keys).

### ECIES Encryption

Assume we have a public key `KEY_ENC_PUB`, data `DATA_ORIG` to be encrypted and a `SHARED_INFO_1` and `SHARED_INFO_2` constants (`byte[]`) as encryption parameters. ECIES encryption works in a following way:

1. Generate an ephemeral key pair:
    ```java
    EPH_KEYPAIR = (KEY_EPH_PRIV, KEY_EPH_PUB).
    ```
2. Derive base secret key (in this step, we do not trim the key to 16b only, we keep all 32b).
    ```java
    SecretKey KEY_BASE = ECDH.phase(KEY_EPH_PRIV, KEY_ENC_PUB)
    ```
3. Derive a secret key using X9.63 KDF function (using SHA256 internally). When calling the KDF, we use `SHARED_INFO_1` together with `KEY_EPH_PUB` value (as raw `byte[]`) as an `info` parameter.
    ```java
    byte[] INFO = Bytes.concat(SHARED_INFO_1, KEY_EPH_PUB);
    SecretKey KEY_SECRET = KDF_X9_63_SHA256.derive(KEY_BASE, INFO)
    ```
4. Split the 32 bytes long `KEY_SECRET` to two 16B keys. The first part is used as an encryption key `KEY_ENC`. The second part is used as MAC key `KEY_MAC`.
    ```java
    byte[] KEY_SECRET_BYTES = KeyConversion.getBytes(KEY_SECRET);
    SecretKey KEY_ENC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET, 0, 16));
    SecretKey KEY_MAC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET, 16, 16));
    ```
5. Compute the encrypted data using AES, with zero `iv` value.
    ```java
    byte[] iv = ByteUtils.zeroBytes(16);
    byte[] DATA_ENCRYPTED = AES.encrypt(DATA_ORIG, iv, KEY_ENC)
    ```
6. Compute the MAC of encrypted data, include `SHARED_INFO_2`.
    ```java
    byte[] DATA = Bytes.concat(DATA_ENCRYPTED, SHARED_INFO_2);
    byte[] MAC = Mac.hmacSha256(KEY_MAC, DATA)
    ```
7. Prepare ECIES payload.
    ```java
    EciesPayload payload = (DATA_ENCRYPTED, MAC, KEY_EPH_PUB)
    ```

### ECIES Decryption

Assume we have a private key `KEY_ENC_PRIV`, encrypted data as an instance of the ECIES payload `(DATA_ENCRYPTED, MAC, KEY_EPH_PUB)` and a `SHARED_INFO_1` and `SHARED_INFO_2` constants (`byte[]`) as decryption parameters. ECIES decryption works in a following way:

1. Derive base secret key from the private key and ephemeral public key from the ECIES payload (in this step, we do not trim the key to 16b only, we keep all 32b).
    ```java
    SecretKey KEY_BASE = ECDH.phase(KEY_ENC_PRIV, KEY_EPH_PUB)
    ```
2. Derive a secret key using X9.63 KDF function (using SHA256 internally). When calling the KDF, we use `KEY_EPH_PUB` value (as raw `byte[]`) as an `info` parameter.
    ```java
    byte[] INFO = Bytes.concat(SHARED_INFO_1, KEY_EPH_PUB);
    SecretKey KEY_SECRET = KDF_X9_63_SHA256.derive(KEY_BASE, INFO)
    ```
3. Split the 32 bytes long `KEY_SECRET` to two 16B keys. The first part is used as an encryption key `KEY_ENC`. The second part is used as MAC key `KEY_MAC`.
    ```java
    byte[] KEY_SECRET_BYTES = KeyConversion.getBytes(KEY_SECRET);
    SecretKey KEY_ENC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET_BYTES, 0, 16));
    SecretKey KEY_MAC = KeyConversion.secretKeyFromBytes(ByteUtils.subarray(KEY_SECRET_BYTES, 16, 16));
    ```
4. Validate the MAC value in payload against expected MAC value. Include `SHARED_INFO_2`. If the MAC values are different, terminate the decryption.
    ```java
    byte[] DATA = Bytes.concat(DATA_ENCRYPTED, SHARED_INFO_2);
    byte[] MAC_EXPECTED = Mac.hmacSha256(KEY_MAC, DATA);
    if (MAC_EXPECTED != MAC) {
        throw EciesException("Invalid MAC"); // terminate the validation with an error
    }
    ```
5. Decrypt the data using AES, with zero `iv` value.
    ```java
    byte[] iv = ByteUtils.zeroBytes(16);
    byte[] DATA_ORIG = AES.decrypt(DATA_ENCRYPTED, iv, KEY_ENC)
    ```

### Client-Server Implementation

Practical implementation of ECIES encryption in PowerAuth accounts for a typical request-response cycle, since encrypting RESTful API requests and responses is the most common use-case.

Client implementation creates an encryptor object that allows encrypting the request and decrypting the response. When encrypting the request, encryptor object accepts a `byte[]` and a public key (for example, `MASTER_SERVER_PUBLIC_KEY`) and produces an instance of `EciesPayload` class. After it receives an encrypted response from the server, which is essentially another instance of `EciesPayload`, it is able to use the original encryption context (the shared encryption keys) to decrypt the response.

Server implementation creates a decryptor object that allows decrypting the original request data and encrypting the response. When server receives an encrypted request, essentially as an `EciesPayload` instance again, it uses a private key (for example, `MASTER_SERVER_PRIVATE_KEY`) to decrypt the original bytes and uses the encryption context to encrypt a response to the client.

Since the client and server use the same encryption context, the ephemeral public key needs to be only sent with the request from the client. Response may only contain encrypted data and MAC value.

Each encryption context can only be used once, for a single request-response cycle.

### Structure of EciesPayload

The structure of the `EciesPayload` is following:

```java
public class EciesPayload {
    private byte[] encryptedData;
    private byte[] mac;
    private byte[] ephemeralPublicKey;
}
```

The typical JSON encoded request is following:

```json
{
    "ephemeralPublicKey" : "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
    "encryptedData" : "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
    "mac" : "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

The JSON response is similar, but without "ephemeralPublicKey" field:

```json
{
    "encryptedData" : "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
    "mac" : "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

## ECIES Scopes

PowerAuth protocol defines two basic usage scopes for ECIES encryption:

- In "application scope", ECIES encryption is available for a whole PowerAuth Client lifetime. In other words, your application can use this mode anytime in its lifetime. 
- In "activation scope", ECIES encryption is available once the PowerAuth Client has a valid activation. In this mode, the encryptor is cryptographically bound to keys exchanged during the activation process.

### Application scope

ECIES in application scope has following configuration of parameters:

- `KEY_ENC_PUB` is `KEY_SERVER_MASTER_PUBLIC`
- `SHARED_INFO_1` is a pre-shared constant and is different for each endpoint (see [Pre-shared constants](#pre-shared-constants)) 
- `SHARED_INFO_2` is calculated from `APPLICATION_SECRET`:
  ```java
  byte[] SHARED_INFO_2 = Hash.sha256(APPLICATION_SECRET);
  ```

*Note that the `APPLICATION_SECRET` constant is in Base64 form, so we need to reinterpret that string as a sequence of ASCII encoded bytes.*

HTTP header example:
```
X-PowerAuth-Encryption: PowerAuth version="3.0", application_key="UNfS0VZX3JhbmRvbQ=="
```

### Activation scope

ECIES in activation scope has following configuration of parameters:

- `KEY_ENC_PUB` is `KEY_SERVER_PUBLIC` (e.g. key which is unique for each activation)
- `SHARED_INFO_1` is a pre-shared constant and is different for each endpoint (see [Pre-shared constants](#pre-shared-constants)) 
- `SHARED_INFO_2` is calculated from `APPLICATION_SECRET` and `KEY_TRANSPORT`:
  ```java
  byte[] SHARED_INFO_2 = Mac.hmacSha256(KEY_TRANSPORT, APPLICATION_SECRET);
  ```
  
*Note that the `APPLICATION_SECRET` constant is in Base64 form, so we need to reinterpret that string as a sequence of ASCII encoded bytes.*

HTTP header example:
```
X-PowerAuth-Encryption: PowerAuth version="3.0", application_key="UNfS0VZX3JhbmRvbQ==", activation_id="c564e700-7e86-4a87-b6c8-a5a0cc89683f"
```
Note, that the header must not be added to the request, when ECIES encryption is combined with [PowerAuth Signature](./Computing-and-Validating-Signatures.md).
  
### Pre-shared constants

PowerAuth protocol defines following `SHARED_INFO_1` (also called as `sh1` or `sharedInfo1`) constants for its own internal purposes:

| RESTful endpoint                      | ECIES scope  | `SHARED_INFO_1` value | 
| ------------------------------------- | ------------ | --------------------- | 
| `/pa/v3/activation/create` (level 1)  | application  | `/pa/generic/application` |
| `/pa/v3/activation/create` (level 2)  | application  | `/pa/activation` |
| `/pa/v3/upgrade`                      | activation   | `/pa/upgrade` |
| `/pa/v3/vault/unlock`                 | activation   | `/pa/vault/unlock` |
| `/pa/v3/token/create`                 | activation   | `/pa/token/create` |

On top of that, following constants can be used for application-specific purposes:

| Purpose                                  | ECIES scope  | `SHARED_INFO_1` value | 
| ---------------------------------------- | ------------ | --------------------- | 
| Generic encryptor for application scope  | application  | `/pa/generic/application` |
| Generic encryptor for activation scope   | activation   | `/pa/generic/activation` |

