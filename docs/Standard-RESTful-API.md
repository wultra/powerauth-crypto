# PowerAuth Standard RESTful API

In order to assure a standard behavior of various PowerAuth implementations, fixed endpoint and request/response structure between PowerAuth Client and Intermediate Server Application is specified for PowerAuth protocol.

While the PowerAuth Client technically communicates with an Intermediate Server Application, all response data are actually built in PowerAuth Server and Intermediate Server Application just forwards data back and forth. Therefore, we will further assume that the phrase "PowerAuth Server responds to PowerAuth Client" is a shortcut for "Intermediate Server Application requests a response from PowerAuth Server and forwards the response to PowerAuth Client".

Each PowerAuth implementation that is located on a specific base URL then has `/pa/` prefixed endpoints by convention.

Following endpoints are published in PowerAuth Standard RESTful API (protocol version 3):

- [`/pa/v3/activation/create`](#initiate-activation) - Create a new activation, perform a key exchange based on activation code.
- [`/pa/v3/activation/status`](#activation-status) - Query for an activation status.
- [`/pa/v3/activation/remove`](#activation-remove) - Remove an activation (requires authentication).
- [`/pa/v3/token/create`](#create-token) - Create a token (requires authentication and encryption).
- [`/pa/v3/token/remove`](#remove-token) - Remove a token (requires authentication).
- [`/pa/v3/vault/unlock`](#vault-unlock) - Get a key to unlock secure vault (requires authentication and encryption).
- [`/pa/v3/signature/validate`](#validate-signature) - Validate a signature (requires authentication).
- [`/pa/v3/upgrade/start`](#upgrade-start) - Start a protocol upgrade (requires encryption).
- [`/pa/v3/upgrade/commit`](#upgrade-commit) - Commits a protocol upgrade (requires authentication).
- [`/pa/v3/recovery/confirm`](#confirm-recovery) - Confirm a recovery code (requires authentication and encryption).

Before you continue, you can also read [End-To-End encryption](./End-To-End-Encryption.md) and [Computing and Validating Signatures](./Computing-and-Validating-Signatures.md) documents, describing encryption and authentication, used in the RESTful API.

## Error handling

PowerAuth Standard RESTful API uses a unified format for error response body, accompanied with an appropriate HTTP status code. Besides the HTTP error codes that application server may return regardless of server application (such as 404 when resource is not found or 503 when server is down), following status codes may be returned:

| Code | Description |
|------|-------------|
| 200  | OK response, no issues |
| 400  | Issue with a request format, or issue of the business logic |
| 401  | Unauthorized, signature validation failed for authenticated endpoints |

All error responses that are produced by the PowerAuth Standard RESTful API have following body:

```json
{
    "status": "ERROR",
    "responseObject": {
        "code": "ERROR_CODE",
        "message": "ERROR_MESSAGE_IN_ENGLISH"
    }
}
```

Note that in case of PowerAuth, the code and message is usually very generic and does not provide a lot of information. Please consult the server log for details. On application level, use HTTP status codes to determine the type of the issue and present appropriate message to the user.

## Initiate activation

Exchange the public keys between PowerAuth Client and PowerAuth Server.

Application activation is a process of key exchange between a PowerAuth Client and a PowerAuth Server. During this process, an "activation record" is created on the PowerAuth Server and related keys are stored on a PowerAuth Client.

PowerAuth Client sends following data on the server:

- Request values encrypted with ECIES level 2 encryption:
    - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
    - `devicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC`
    - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
- Request encrypted with ECIES level 1 encryption:
    - `activationType` - Assume that standard activation is using "CODE" constant as an activation type.
    - `activationCode` - Represents an `ACTIVATION_CODE` value
- Not encrypted values (HTTP header)
    - `applicationKey` - Represents an application with a given `APPLICATION_KEY`

PowerAuth Server decrypts both levels of encryption and returns following data:

- Response values encrypted with ECIES level 2 encryption
    - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
    - `serverPublicKey` - Public key `KEY_SERVER_PUBLIC` of the server.
    - `ctrData` - Initial value for hash-based counter.
- Response values encrypted with ECIES level 1 
    - `customAttributes` - Structure for application-specific data.
    
After receiving the response, PowerAuth Client decrypts both layers of response data and continues with the activation process. You can check the documentation for an [Activation](./Activation.md) for more details.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/create`  |
| ECIES (level 1)   | `application, sh1="/pa/generic/application"` |
| ECIES (level 2)   | `application, sh1="/pa/activation"`          |

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Encryption: PowerAuth version="3.0", application_key="UNfS0VZX3JhbmRvbQ=="`

JSON request object before ECIES level 2 encryption:
```json
{
    "devicePublicKey": "RUNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
    "activationName": "My iPhone",
    "extras": "Any data in string format"
}
```

JSON request object before ECIES level 1 encryption. The `activationData` field contains previous object after the ECIES level 2 encryption:
```json
{
    "activationType": "CODE",
    "identityAttributes": {
        "code": "VVVVV-VVVVV-VVVVV-VTFVA"
    },
    "activationData": {
        "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
        "encryptedData": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
        "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
    }
}
```

The actual request payload then looks like:
```json
{
    "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWN0ASKDHsakdhksajhdkjashdkhKSDJhAKSDHKSADHkahdskahdakhdKADHakjhdadsaX9JRaAhbG9duZ==",
    "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

JSON response (before any decryption):
```json
{
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWNSDKJHSDkhadkhSDKJHASDKHSADkjhasdkhSADKHASKDHASKDJHASDKHJ0aX9JRaAhbG9duZ==",
    "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

JSON response after ECIES level 1 decryption:
```json
{
    "customAttributes": {
        "any-key": "any-value"
    },
    "activationData": {
        "encryptedData": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
        "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
    }
}
```

The `activationData` contains an encrypted level 2 response. So, the JSON response after ECIES level 2 decryption is following:
```json
{
    "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
    "serverPublicKey": "NESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
    "ctrData": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J==",
    "activationRecovery": {
        "recoveryCode": "VVVVV-VVVVV-VVVVV-VTFVA",
        "puk": "0123456789"
    }
}
```
> Note that `"activationRecovery"` part of the response is optional and depends on whether the [Activation Recovery](Activation-Recovery.md) feature is enabled on the PowerAuth Server.

## Activation status

Get the status of an activation with given activation ID. The PowerAuth Server response contains an encrypted activation status blob. More information about the format of status blob and encryption can be found in the [chapter on activation status cryptography](./Activation-Status.md).

This endpoint also returns a `customObject` object with custom application specific data. This object may be used for example to provide service specific data (current timestamp, info about service status, ...) in order to minimize number of required request in practical deployments (for example, mobile banking needs to ask for the service status data on application launch).

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/status`  |

### Request

- Headers
    - `Content-Type: application/json`

```json
{
    "requestObject": {
        "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f"
    }
}
```

### Response

- Status code: `200`
- Headers
    - `Content-Type: application/json`

```json
{
    "status": "OK",
    "responseObject": {
        "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
        "encryptedStatusBlob": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
        "customObject": {
            "_comment": "Any object data, such as timestamp, service status info, etc."
        }
    }
}
```

## Activation remove

Remove an activation with given ID, set it's status to REMOVED. Activation can be removed only after successful verification of the signature.

PowerAuth Client sends an authenticated request using an activation ID - authentication is carried around using the standard PowerAuth signature with at least 2 factors (2FA).

In order to construct the PowerAuth Client signature, use `/pa/activation/remove` as URI identifier part of the signature data.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/status`  |
| Signature uriId   | `/pa/activation/remove`     |

### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body: empty

#### Response

- Status code: `200`
- Headers
    - `Content-Type: application/json`

```json
{
    "status": "OK"
}
```

## Create token

Create a static token which can be used for repeated requests to data resources which support token based authentication.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/token/create`       |
| Signature uriId   | `/pa/token/create`          |
| ECIES             | `activation, sh1="/pa/token/create"` |

### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`

JSON request object, before ECIES encryption (is actually an empty JSON object):
```json
{}
```

Actual JSON request body, after the encryption:
```json
{
    "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWNSDKJHSDkhadkhSDKJHASDKHSADkjhasdkhSADKHASKDHASKDJHASDKHJ0aX9JRaAhbG9duZ==",
    "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

*Note that PowerAuth Signature must be calculated from the final, encrypted data (e.g. it's "encrypt-then-sign" mode).*

#### Response

- Status code: `200`
- Headers
    - `Content-Type: application/json`

JSON response before the decryption:
```json
{
    "mac": "xvJ1Zq0mOtgvVqbspLhWMt2NJaTDZ5GkPBbcDxXRB9M=",
    "encryptedData": "6YkPoxWXQDIHdT5OIQrxMe4+qH+pNec5HlzBacZPAy3fB3fCc25OJAoXIaBOTatVbAcsuToseNanIX3+ZNcyxIEVj16OoawPhm1w=="
}
```

JSON object after the decryption:
```json
{
   "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
}
```


## Remove token

Remove a previously created token.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/token/remove`       |
| Signature uriId   | `/pa/token/remove`          |


### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`

JSON request body:
```json
{
    "requestObject": {
        "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
    }
}
```

#### Response

- Status code: `200`
- Headers
    - `Content-Type: application/json`

JSON response:
```json
{}
```

## Vault unlock

Get the vault unlock key in order to decrypt data stored in the vault, for example the original `KEY_DEVICE_PRIVATE`.

PowerAuth Client sends an encrypted and authenticated request using an activation ID - authentication is carried around using the standard PowerAuth signature with at least 2 factors (2FA). The combination of "possession" and "knowledge" factors is mandatory.

In response, PowerAuth Server sends a `KEY_ENCRYPTION_VAULT` key encrypted using `KEY_TRANSPORT` (see the [PowerAuth Key Derivation](./Key-derivation.md) chapter for details).

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_TRANSPORT)`

PowerAuth Client can later decrypt the key using the inverse mechanism:

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_TRANSPORT)`

_Note: The protection of the vault encryption key transmission, is based on our ECIES scheme. So, it's no longer required to deduce an additional decryption keys as it was in PowerAuth protocol V2. The additional `KEY_TRANSPORT` encryption is added to the scheme only due the fact, that we don't want to expose such a sensitive key in plaintext, in managed runtime environments (like Java or Objective-C)._

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/vault/unlock`       |
| Signature uriId   | `/pa/vault/unlock`         |
| ECIES             | `activation, sh1="/pa/vault/unlock"` |

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`


JSON request before ECIES encryption:
```json
{
    "reason": "ADD_BIOMETRY"
}
```

You can provide following reasons for a vault unlocking:

- `ADD_BIOMETRY` - call was used to enable biometric authentication.
- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for ECDSA signatures.
- `RECOVERY_CODE` - call was used to unlock recovery code.

Actual JSON request body, after the encryption:
```json
{
    "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWNSDKJHSDkhadkhSDKJHASDKHSADkjhasdkhSADKHASKDHASKDJHASDKHJ0aX9JRaAhbG9duZ==",
    "mac": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```
*Note that PowerAuth Signature must be calculated from the final, encrypted data (e.g. it's "encrypt-then-sign" mode).*

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

JSON response after the decryption:
```json
{
    "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
    "encryptedVaultEncryptionKey": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```

## Validate signature

Validate a PowerAuth signature using `X-PowerAuth-Authorization` HTTP header.

The HTTP request can use the `GET`, `POST`, `PUT` or `DELETE` method. 

Following signature types are supported:
- `possession_knowledge`
- `possession_biometry`
- `possession_knowledge_biometry`

The request body should contain data used for computing the signature.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`, `GET`, `PUT`, `DELETE` |
| Resource URI      | `/pa/v3/signature/validate`    |
| Signature uriId   | `/pa/signature/validate`       |

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`

JSON request body can contain any data:
```json
{ 
  "... signed request data"
}
```

### Response (validation succeeded)

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

```json
{
    "status": "OK"
}
```

### Response (validation failed)

- Status Code: `401`
- Headers:
    - `Content-Type: application/json`

```json
{
    "status": "ERROR",
    "responseObject": {
        "code": "POWERAUTH_AUTH_FAIL",
        "message": "Signature validation failed"
    }
}
```


## Upgrade Start

Start a process to upgrade from protocol version 2, to version 3. PowerAuth Client simply receives an initial value for `CTR_DATA`, a hash-based counter.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/upgrade/start`      |
| ECIES             | `activation, sh1="/pa/upgrade"` |

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Encryption: PowerAuth ...`

JSON request body before the encryption (an empty JSON):
```json
{}
```

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

JSON response after the decryption:
```json
{
    "ctrData": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J=="
}
```


## Upgrade Commit

Finish an upgrade process. In this step, the PowerAuth signature must be calculated with respecting a new, protocol V3 scheme (e.g. must use `CTR_DATA` instead of old `CTR`).

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/upgrade/commit`     |
| Signature uriId   | `/pa/upgrade/commit`        |

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`

JSON request body (an empty JSON):
```json
{}
```

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

JSON response body (an empty JSON):
```json
{}
```


## Confirm Recovery

Confirm a recovery code created for a recovery postcard. The recovery code is confirmed once user receives a postcard with recovery code and PUKs. 

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/recovery/confirm`   |
| Signature uriId   | `/pa/recovery/confirm`      |
| ECIES             | `activation, sh1="/pa/recovery/confirm"` |

### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`

JSON request before ECIES encryption:
```json
{
    "recoveryCode": "VVVVV-VVVVV-VVVVV-VTFVA"
}
```

Actual JSON request body after the encryption:
```json
{
    "ephemeralPublicKey": "BPZvFnVgImV2LLIdxRoGPQvp8m0uG9cIwNhs11mXWT+sBcILDYgDuj0DagbS8yNbTju07PPscc/eE7zjQ/0sPSo=",
    "encryptedData": "fuDZz3jqtJ40JjKHek/57gt3dL4XyLWVq9CYupEudCOnTvo6yq57oW9VWR1/e+Ih",
    "mac":"dL9IGDMoOuyqScxWv9R5XpOj8B/wRNKoLEo5eL8GonA="
}
```

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`
    
JSON response before ECIES decryption:
```json
{
    "mac": "ct78kSghyrL+b7N/bpNNI5GRt595xU5Y2qlGEG+j+1U=",
    "encryptedData": "7LK7qs+OK0cfQPZlkzl2G8z5/IZx0SHhI/BPYFhhxqE="
}
```

JSON response after the decryption:
```json
{
    "alreadyConfirmed" : false
}
```