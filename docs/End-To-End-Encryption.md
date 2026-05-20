# End-To-End Encryption

This document describes PowerAuth **End-To-End Encryption**.

The End-to-End encryption is used for sending encrypted data to the server and back to the client in a request-response cycle.

PowerAuth End-to-End encryption consists of two phases:

1. Temporary shared secret establishment - the client and server agree on shared key `KEY_TEMPORARY_SHARED_SECRET`, the actual process depends on the selected cryptographic algorithm suite.
2. AEAD encryption - the client encrypts the request, sends to the server; the server encrypts the response and sends it to the client.

Both client and server use the same encryption key for authenticated symmetric encryption. See the chapters below for details.

## Temporary Encryption Keys

A temporary encryption key is identified by its identifier, for which the UUID format is used. The temporary key is stored on the server in the database together with its identifier, shared key `KEY_TEMPORARY_SHARED_SECRET` (encrypted) and expiration timestamp.

A single temporary key may be reused for multiple encrypted request/response cycles until it expires (the default expiration period is 5 minutes).

After the temporary key expiration is reached, both client and server must discard the temporary key. This mechanism provides replay protection and forward secrecy.

## Forward Secrecy

Forward secrecy is achieved by using temporary shared secrets.

Because `KEY_TEMPORARY_SHARED_SECRET` is derived when requesting the temporary key from the server and discarded after temporary key expiration, compromise of long-term application or activation keys does not expose traffic outside the temporary key lifetime.

## Basic Definitions

### Constants

- `VERSION` – String with current protocol version (for example `"4.0"`)
- `APPLICATION_KEY` – Application key
- `ACTIVATION_ID` – Optional activation identifier
- `APPLICATION_SECRET` – Application secret (Base64-encoded string, must be decoded to raw bytes before use)
- `SHARED_INFO_1` – Endpoint-specific pre-shared constant
- `TEMPORARY_KEY_ID` – UUID identifying the temporary key
- `KEY_TEMPORARY_SHARED_SECRET` – Temporary shared secret derived via KEM

### Variables

- `PLAINTEXT` – Data to be encrypted
- `ASSOCIATED_DATA` – Plaintext data authenticated by AEAD
- `TIMESTAMP` – Unix timestamp in milliseconds
- `NONCE` – 24 bytes long nonce (a 12 byte `REQUEST_NONCE` concatenated with a 12 byte `RESPONSE_NONCE`)

## Encryption Scopes

PowerAuth defines two scopes for End-To-End encryption:

- **Application scope**
    - Encryption is available without activation (non-personalized use case)
- **Activation scope**
    - Encryption is bound to a specific activation (personalized use case)

Both scopes use identical cryptographic primitives but differ in how `ASSOCIATED_DATA` and `SHARED_INFO_2` are constructed.

## Temporary Shared Secret Establishment

Before encrypting any request, client and server must establish a temporary shared secret.

This is done using [Create New Temporary Key](./Standard-RESTful-API.md#create-new-temporary-key) endpoint in the REST API with KEM-based key exchange.

### Request

```json
{
  "applicationKey": "4QSaLlQ/GphFOQeB2mnOYQ==",
  "activationId": "3b09d6fd-9640-4731-bc99-8324672f4b27",
  "challenge": "Iv6oBttCKqODNy2DPoYCDQ==",
  "sharedSecretRequest": {
    "algorithm": "EC_P384_ML_L5",
    "encapsulationKeys": ["NuIkMs...", "IqWwre..."]
  }
}
```

Supported algorithms: `EC_P384`, `EC_P384_ML_L3`, and `EC_P384_ML_L5`.

### Response

```json
{
  "applicationKey": "4QSaLlQ/GphFOQeB2mnOYQ==",
  "activationId": "3b09d6fd-9640-4731-bc99-8324672f4b27",
  "challenge": "Iv6oBttCKqODNy2DPoYCDQ==",
  "keyId": "dc497e8a-8faa-44bc-a52a-20d8393005d2",
  "sharedSecretResponse": {
    "salt": "GwHlUc4dXvDobaBlInu8gDAQd5fIZiPyYVYt69YUjYo=",
    "encapsulatedKeys": [
      "BIJ8Eoxi2tgxQetJ5h+Eee6K/NGjQdshSK+pul1mOUn9K++xIWU39SkcUc..."
    ]
  },
  "expiration": 1769425623112,
  "serverTime": 1769425681453
}
```

Result:

- Server assigns `TEMPORARY_KEY_ID`, stores the key in the database (with the shared secret encrypted at rest), and returns the identifier to the client.
- Both sides derive the same `KEY_TEMPORARY_SHARED_SECRET`.
- Client stores the temporary key locally until expiration.

Each temporary key is used until expiration, after this a new temporary key is requested for additional encryption request/response cycles.

## Shared Secret Derivation

The shared secret derivation depends on the selected KEM algorithm (which can also be hybrid). The request contains one or more encapsulation keys, and the response also contains one or more encapsulated keys. The derivation is algorithm-independent, and thus it works both for ECDH, ML-KEM, and hybrid schemes, and it can be easily extended with new cryptographic algorithms in the future, too.

For more details see chapter [Shared Secret Derivation](./Shared-Secret-Derivation.md).

## SHARED_INFO_2

`SHARED_INFO_2` binds encryption to application or activation-level secrets.

Note: `APPLICATION_SECRET` is provided as Base64 and must be converted to raw bytes before use.

Application scope:

```java
byte[] SHARED_INFO_2 = Hash.sha3_256(APPLICATION_SECRET);
```

Activation scope:

```java
byte[] SHARED_INFO_2 = Mac.kmac256(KEY_E2EE_SHARED_INFO2, APPLICATION_SECRET, 32, "PA4SH2");
```

## ASSOCIATED_DATA

`ASSOCIATED_DATA` is transmitted in plaintext and authenticated by AEAD.

| Scope       | Calculation                                                                            |
|-------------|----------------------------------------------------------------------------------------|
| Application | `ByteUtils.concatWithSizes(VERSION, APPLICATION_KEY, TEMPORARY_KEY_ID)`                |
| Activation  | `ByteUtils.concatWithSizes(VERSION, APPLICATION_KEY, ACTIVATION_ID, TEMPORARY_KEY_ID)` |

The same value is used for request and response.

## Structure of Encrypted Payload

### Encrypted Request

Fields:

- `temporaryKeyId`
- `encryptedData`
- `nonce`
- `timestamp`

### Encrypted Response

Fields:

- `encryptedData`
- `timestamp`

The response does not include `nonce` or `temporaryKeyId`, as both are already known from the request context.

## AEAD Encryption (Client Request)

Assume we have:

- `KEY_TEMPORARY_SHARED_SECRET`
- `PLAINTEXT`
- `ASSOCIATED_DATA`
- `SHARED_INFO_1`
- `SHARED_INFO_2`

### Steps

1. Generate timestamp:

```java
long TIMESTAMP = Time.getTimestamp();
byte[] TIMESTAMP_BYTES = ByteUtils.encode(TIMESTAMP);
```

2. Generate nonces:

```java
byte[] REQUEST_NONCE  = Generator.randomBytes(12);
byte[] RESPONSE_NONCE = Generator.randomBytes(12);
byte[] NONCE = Bytes.concat(REQUEST_NONCE, RESPONSE_NONCE);
byte[] IV = REQUEST_NONCE;
```

Client must ensure that both request and response nonces are unique and must maintain per-temporary-key history to prevent nonce reuse. Both request and response nonces must never be reused with the same temporary key.

3. Build Key Context and AEAD Associated Data:

```java
byte[] KC = Bytes.concat(VERSION, SHARED_INFO_1, NONCE);

byte[] AD = Bytes.concat(
    ASSOCIATED_DATA,
    ByteUtils.concatWithSizes(TIMESTAMP_BYTES, NONCE, SHARED_INFO_2)
);
```

4. Encrypt using AEAD:

```java
byte[] CIPHERTEXT = AEAD.seal(
    KEY_TEMPORARY_SHARED_SECRET,
    KC,
    IV,
    AD,
    PLAINTEXT
);
```

### Request Payload

```json
{
  "temporaryKeyId": "UUID",
  "encryptedData": "Base64",
  "nonce": "Base64",
  "timestamp": "long"
}
```

## AEAD Decryption (Server Request)

Given:

- `KEY_TEMPORARY_SHARED_SECRET`
- `(encryptedData, nonce, timestamp)`
- `ASSOCIATED_DATA`
- `SHARED_INFO_1`
- `SHARED_INFO_2`

Steps:

1. Extract IV from first 12 bytes of `NONCE`.
2. Recompute `KC` and `AD` using same algorithm as described above.
3. Decrypt:

```java
byte[] CIPHERTEXT_NONCE = AEAD.extractNonce(encryptedData);
if (!Arrays.equals(CIPHERTEXT_NONCE, IV)) {
        throw new SecurityException("Invalid ciphertext nonce");
}
byte[] PLAINTEXT = AEAD.open(
    KEY_TEMPORARY_SHARED_SECRET,
    KC,
    IV,
    AD,
    encryptedData
);
```

If authentication fails, terminate processing.

## AEAD Encryption (Server Response)

For the response:

- Reuse the same `NONCE`
- Set `IV = RESPONSE_NONCE`
- Generate new `TIMESTAMP`
- Rebuild `AD` with response timestamp
- Encrypt response payload using AEAD

### Response Payload

```json
{
  "encryptedData": "l7f9qtwZ9v0uZN6Kzfxwy32hE3TQ4m1ALwuYHMbBI5cS...",
  "timestamp": 1769425681453
}
```

## Replay Protection

### Overview

PowerAuth prevents replay attacks in end-to-end encryption and MAC token authentication by combining timestamp validation with unique value tracking.

Every encrypted request must include a `TIMESTAMP` (Unix timestamp in milliseconds). The server rejects requests with timestamps outside a ±5 minute window. Additionally, the server records each unique value after accepting a request and rejects duplicates.

### `pa_unique_values` Table

The server maintains a `pa_unique_values` table to track used unique values:

| Column             | Type         | Description                                          |
|--------------------|--------------|------------------------------------------------------|
| `type`             | INT(11)      | Type of unique value (see below)                     |
| `identifier`       | VARCHAR(37)  | Identifier scoped to the record type                 |
| `unique_value`     | VARCHAR(255) | The unique value being tracked                       |
| `timestamp_expire` | DATETIME     | Expiration timestamp for this record                 |

#### Record Types

| Type | Name                    | `identifier`       | `unique_value`       |
|------|-------------------------|--------------------|----------------------|
| `1`  | TOKEN                   | `TOKEN_ID`         | `NONCE`              |
| `2`  | ECIES_APPLICATION_SCOPE | `APPLICATION_KEY`  | `KEY_EPH_PUB+NONCE`  |
| `3`  | ECIES_ACTIVATION_SCOPE  | `ACTIVATION_ID`    | `KEY_EPH_PUB+NONCE`  |
| `4`  | ECIES_WITH_TEMP_KEY     | `TEMPORARY_KEY_ID` | `KEY_EPH_PUB+NONCE`  |
| `5`  | AEAD_V4                 | `TEMPORARY_KEY_ID` | `NONCE`              |

The server runs a periodic cleanup job to remove records where `timestamp_expire` is less than the current timestamp.

> Keep in mind that the expiration of the temporary key used in ECIES or AEAD encryption schemes must match the expiration of E2EE-related records in `pa_unique_values`. If the temporary key remains valid beyond the duration defined by the `EXPIRATION` constant, it may allow for replay attacks.

### Validation for AEAD_V4

Let `EXPIRATION = 5 minutes`, `IDENTIFIER = TEMPORARY_KEY_ID`, `CURRENT_TIMESTAMP = current server time`.

1. Verify `TIMESTAMP` is present — reject if missing (required for V4).
2. Verify `TIMESTAMP` is within `CURRENT_TIMESTAMP ± EXPIRATION` — reject if outside range.
3. Look up a record with `type = 5`, `identifier = TEMPORARY_KEY_ID`, `unique_value = NONCE` in `pa_unique_values`.
   - If record exists — reject (duplicate nonce).
   - If no record — continue.
4. Insert new record into `pa_unique_values` with `EXPIRATION` as TTL.
5. Accept the request.

### Validation for MAC Tokens

Let `EXPIRATION = 5 minutes` (for protocol 3.2+), `EXTENDED_EXPIRATION = 120 minutes` (for protocol 3.0 and 3.1).

1. Verify the token header is correctly calculated — reject if invalid.
2. Verify `TIMESTAMP` is within the acceptable range:
   - Protocol 3.0/3.1: within `CURRENT_TIMESTAMP ± EXTENDED_EXPIRATION`
   - Protocol 3.2+: within `CURRENT_TIMESTAMP ± EXPIRATION`
3. Look up a record with `type = 1`, `identifier = TOKEN_ID`, `unique_value = NONCE` in `pa_unique_values`.
   - If record exists — reject (duplicate nonce).
   - If no record — continue.
4. Insert new record into `pa_unique_values` using `EXPIRATION` (or `EXTENDED_EXPIRATION` for older protocols) as TTL.
5. Accept the request.

### Client Validation

Client must also validate the response timestamp and relies on AEAD authentication to ensure response freshness and integrity.

## Client–Server Implementation

### Client

1. Obtain temporary shared secret from the temporary key.
2. Encrypt request using AEAD with a temporary shared secret.
3. Send encrypted payload and wait for response from the server.
4. Receive encrypted response.
5. Decrypt response.

### Server

1. Receive encrypted request.
2. Look up temporary shared secret in the database using the temporary key identifier in the request.
3. Validate timestamp and nonce uniqueness to avoid replay attacks.
4. Decrypt request.
5. Encrypt response using the same temporary shared secret.

## Encrypted Request Example

```json
{
  "temporaryKeyId": "dc497e8a-8faa-44bc-a52a-20d8393005d2",
  "encryptedData" : "H1nYcs4WqSC8/Vo3lZYd/wHAb8qC1yHOlzjQlkUOqmu1...",
  "nonce" : "H1nYcs4WqSC8/Vo3M0VBe+RyQ1FGlw1l",
  "timestamp" : 1769422877113
}
```

HTTP header in application scope:

```
X-PowerAuth-Encryption: PowerAuth version="4.0", application_key="UNfS0VZX3JhbmRvbQ=="
```

HTTP header in activation scope:

```
X-PowerAuth-Encryption: PowerAuth version="4.0", application_key="UNfS0VZX3JhbmRvbQ==", activation_id="3b09d6fd-9640-4731-bc99-8324672f4b27"
```

## Encrypted Response Example

```json
{
  "encryptedData": "l7f9qtwZ9v0uZN6Kzfxwy32hE3TQ4m1ALwuYHMbBI5cS...",
  "timestamp": 1691762307385
}
```

Responses do not use encryption headers.

### Pre-Shared Constants

`SHARED_INFO_1` is a pre-shared endpoint-specific constant ensuring key separation.

Following constants can be used for application-specific purposes:

| Purpose                       | Scope       | Value                     |
|-------------------------------|-------------|---------------------------|
| Generic application encryptor | Application | `/pa/generic/application` |
| Generic activation encryptor  | Activation  | `/pa/generic/activation`  |

Concrete REST endpoints define their own `SHARED_INFO_1` constants to ensure cryptographic separation between use cases.

List of defined constants:

| Endpoint           | Scope       | SHARED_INFO_1         |
|--------------------|-------------|-----------------------|
| Activation layer 2 | Application | `/pa/activation`      |
| Upgrade start      | Application | `/pa/upgrade/start`   |
| Vault unlock       | Activation  | `/pa/vault/unlock`    |
| Create token       | Activation  | `/pa/token/create`    |
| Change password    | Activation  | `/pa/password/change` |
| Enable biometry    | Activation  | `/pa/biometry/add`    |