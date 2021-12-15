# PowerAuth Standard RESTful API

<!-- TEMPLATE api -->

In order to assure a standard behavior of various PowerAuth implementations, fixed endpoint and request/response structure between PowerAuth Client and Intermediate Server Application is specified for the PowerAuth protocol.

Each PowerAuth implementation that is located on a specific base URL then has `/pa/` prefixed endpoints by convention.

<!-- begin remove -->
The following endpoints are published in PowerAuth Standard RESTful API (protocol version 3):

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
<!-- end -->

## Security Features

Before you continue, we suggest reading the [End-To-End encryption](./End-To-End-Encryption.md) and [Computing and Validating Signatures](./Computing-and-Validating-Signatures.md) documents, describing encryption and authentication mechanism used in the RESTful APIs.

## Content Type

All requests and responses use the JSON format. The following header needs to be set in the request:

```
Content-Type: application/json
```

## Error Handling

PowerAuth Standard RESTful API uses a unified format for error response body, accompanied with an appropriate HTTP status code. Besides the HTTP error codes that application server may return regardless of server application (such as 404 when resource is not found or 503 when server is down), the following status codes may be returned:

| Code | Description |
|------|-------------|
| 200  | OK response, no issues |
| 400  | Issue with a request format, or issue of the business logic |
| 401  | Unauthorized, signature validation failed for authenticated endpoints |

All error responses that produced by the PowerAuth Standard RESTful API have the following structure:

```json
{
    "status": "ERROR",
    "responseObject": {
        "code": "ERROR_CODE",
        "message": "ERROR_MESSAGE_IN_ENGLISH"
    }
}
```

<!-- begin box info -->
The code and message are usually very generic and do not provide a lot of information. Please consult the server log for details. On application level, use the HTTP status code to determine the type of the issue and present appropriate message to the user.
<!-- end -->

## API Resources

<!-- begin api POST /pa/v3/activation/create -->
### Initiate Activation

Exchange the public keys between PowerAuth Client and PowerAuth Server.

Application activation is a process of key exchange between a PowerAuth Client and a PowerAuth Server. During this process, an "activation record" is created on the PowerAuth Server and related keys are stored on a PowerAuth Client.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/create`  |
<!-- end -->

#### Request

PowerAuth Client sends the following data on the server:

- Request values encrypted with ECIES level 2 encryption:
    - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
    - `devicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC`
    - `activationOtp` - Optional authentication OTP used for additional user authentication.
    - `platform` - User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
    - `deviceInfo` - Information about user device, e.g. `iPhone12,3`.
    - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
- Request encrypted with ECIES level 1 encryption:
    - `activationType` - Assume that standard activation is using "CODE" constant as an activation type.
    - `activationCode` - Represents an `ACTIVATION_CODE` value
- Not encrypted values (HTTP header)
    - `applicationKey` - Represents an application with a given `APPLICATION_KEY`

PowerAuth Server decrypts both levels of encryption and returns the following data:

- Response values encrypted with ECIES level 2 encryption
    - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
    - `serverPublicKey` - Public key `KEY_SERVER_PUBLIC` of the server.
    - `ctrData` - Initial value for hash-based counter.
- Response values encrypted with ECIES level 1
    - `customAttributes` - Structure for application-specific data.

After receiving the response, PowerAuth Client decrypts both layers of response data and continues with the activation process. You can check the documentation for an [Activation](./Activation.md) for more details.

##### Encryption Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| ECIES (level 1)   | `application, sh1="/pa/generic/application"` |
| ECIES (level 2)   | `application, sh1="/pa/activation"`          |

##### Encryption Headers

```
X-PowerAuth-Encryption: PowerAuth version="3.1", application_key="UNfS0VZX3JhbmRvbQ=="
```

##### Body

The JSON request object before ECIES level 2 encryption:

```json
{
    "devicePublicKey": "RUNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
    "activationName": "My iPhone",
    "activationOtp": "12345678",
    "platform": "ios",
    "deviceInfo": "iPhone12,3",
    "extras": "Any data in string format"
}
```

The JSON request object before ECIES level 1 encryption. The `activationData` field contains the previous object after the ECIES level 2 encryption:

```json
{
    "activationType": "CODE",
    "identityAttributes": {
        "code": "VVVVV-VVVVV-VVVVV-VTFVA"
    },
    "activationData": {
        "ephemeralPublicKey" : "A5Iuit2vV1zgLb/ewROYGEMWxw4zjSoM2e2dO6cABY78",
        "encryptedData" : "7BzoLuLYKZrfFfhlom1zMA==",
        "mac" : "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
        "nonce" : "v1y015uEP5RuT2g9RS6LIw=="
    }
}
```

The actual request payload then looks like:

```json
{
    "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWN0ASKDHsakdhksajhdkjashdkhKSDJhAKSDHKSADHkahdskahdakhdKADHakjhdadsaX9JRaAhbG9duZ==",
    "mac" : "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "nonce" : "v1y015uEP5RuT2g9RS6LIw=="
}
```

#### Response 200

The JSON response (before any decryption) is the following:

```json
{
    "encryptedData": "19gyYaW5ZhdGlvblkb521fYWNSDKJHSDkhadkhSDKJHASDKHSADkjhasdkhSADKHASKDHASKDJHASDKHJ0aX9JRaAhbG9duZ==",
    "mac": "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI="
}
```

The JSON response after ECIES level 1 decryption unwraps to:

```json
{
    "customAttributes": {
        "any-key": "any-value"
    },
    "activationData": {
        "encryptedData": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
        "mac": "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI="
    }
}
```

The `activationData` contains an encrypted level 2 response. So, the JSON response after ECIES level 2 decryption is the following:

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

<!-- begin box info -->
The `activationRecovery` response element is optional and depends on whether the [Activation Recovery](Activation-Recovery.md) feature is enabled on the PowerAuth Server or not.
<!-- end -->
<!-- end -->

<!-- begin api POST /pa/v3/activation/status -->
### Activation Status

Get the status of an activation with given activation ID. The PowerAuth Server response contains an encrypted activation status blob. More information about the format of status blob and encryption can be found in the [chapter on activation status cryptography](./Activation-Status.md).

This endpoint also returns a `customObject` object with custom application specific data. This object may be used for example to provide service specific data (current timestamp, info about service status, ...) in order to minimize number of required request in practical deployments (for example, mobile banking needs to ask for the service status data on application launch).

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/status`  |
<!-- end -->

#### Request

```json
{
    "requestObject": {
        "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
        "challenge": "MDEyMzQ1Njc4OWFiY2RlZg=="
    }
}
```

#### Response 200

```json
{
    "status": "OK",
    "responseObject": {
        "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
        "encryptedStatusBlob": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ==",
        "nonce": "MDEyMzQ1Njc4OWFiY2RlZg==",
        "customObject": {
            "_comment": "Any object data, such as timestamp, service status info, etc."
        }
    }
}
```
<!-- end -->

<!-- begin api POST /pa/v3/activation/status -->
### Activation Remove

Remove an activation with given ID, set the activation status to `REMOVED`. Activation can be removed only after successful verification of the signature.

PowerAuth Client sends an authenticated request using an activation ID. Authentication is carried around using the standard PowerAuth signature with at least two factors (2FA).

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/activation/status`  |
<!-- end -->

#### Request

##### Signature Parameters

In order to construct the PowerAuth Client signature, use the `POST` method and `/pa/activation/remove` as URI identifier.

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/activation/remove`     |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

Any, the value is ignored but must match the signature header.

#### Response 200

```json
{
    "status": "OK"
}
```
<!-- end -->

<!-- begin api POST /pa/v3/token/create -->
### Create Token

Create a static token which can be used for repeated requests to data resources which support token based authentication.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/token/create`       |
<!-- end -->

#### Request

##### Signature and Encryption Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/token/create`          |
| ECIES             | `activation, sh1="/pa/token/create"` |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request object, before an ECIES encryption (an empty JSON object):

```json
{}
```

Actual JSON request body, after the encryption:

```json
{
    "ephemeralPublicKey" : "A5Iuit2vV1zgLb/ewROYGEMWxw4zjSoM2e2dO6cABY78",
    "encryptedData" : "7BzoLuLYKZrfFfhlom1zMA==",
    "mac" : "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "nonce" : "v1y015uEP5RuT2g9RS6LIw=="
}
```

<!-- begin box warning -->
When creating a new token, the PowerAuth Signature must be calculated from the final encrypted data ("encrypt-then-sign").
<!-- end -->

#### Response 200

The JSON response before the decryption:

```json
{
    "mac": "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "encryptedData": "6YkPoxWXQDIHdT5OIQrxMe4+qH+pNec5HlzBacZPAy3fB3fCc25OJAoXIaBOTatVbAcsuToseNanIX3+ZNcyxIEVj16OoawPhm1w=="
}
```

The JSON object after the decryption:

```json
{
   "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
}
```
<!-- end -->

<!-- begin api POST /pa/v3/token/remove -->
### Remove Token

Remove a previously created token.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/token/remove`       |
<!-- end -->

#### Request

##### Signature Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/token/remove`          |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{
    "requestObject": {
        "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
    }
}
```

#### Response 200

```json
{}
```
<!-- end -->

<!-- begin api POST /pa/v3/vault/unlock -->
### Vault Unlock

Get the vault unlock key in order to decrypt data stored in the vault, for example the original `KEY_DEVICE_PRIVATE`.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/vault/unlock`       |
<!-- end -->

#### Request

PowerAuth Client sends an encrypted and authenticated request using an activation ID. The authentication is carried around using the standard PowerAuth signature with at least two factors (2FA). The combination of "possession" and "knowledge" factors is supported by default, the biometry may be explicitly allowed by a particular deployment.

In response, PowerAuth Server sends a `KEY_ENCRYPTION_VAULT` key encrypted using `KEY_TRANSPORT` (see the [PowerAuth Key Derivation](./Key-derivation.md) chapter for details).

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_TRANSPORT)`

PowerAuth Client can later decrypt the key using the inverse mechanism:

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_TRANSPORT)`

<!-- begin box info -->
The protection of the vault encryption key transmission, is based on our ECIES scheme. Therefore, it is no longer required to deduce an additional decryption keys as it was in PowerAuth protocol V2. The additional `KEY_TRANSPORT` encryption is added to the scheme only due the fact, that we don't want to expose such a sensitive key in plaintext, in managed runtime environments (like Java or Objective-C).
<!-- end -->

##### Signature and Encryption Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/vault/unlock`         |
| ECIES             | `activation, sh1="/pa/vault/unlock"` |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request before ECIES encryption:

```json
{
    "reason": "ADD_BIOMETRY"
}
```

You can provide the following reasons for a vault unlocking:

- `ADD_BIOMETRY` - call was used to enable biometric authentication.
- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for ECDSA signatures.
- `RECOVERY_CODE` - call was used to unlock recovery code.

An actual JSON request body after the encryption is the following:

```json
{
    "ephemeralPublicKey" : "A5Iuit2vV1zgLb/ewROYGEMWxw4zjSoM2e2dO6cABY78",
    "encryptedData" : "7BzoLuLYKZrfFfhlom1zMA==",
    "mac" : "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "nonce" : "v1y015uEP5RuT2g9RS6LIw=="
}
```

<!-- begin box warning -->
When unlocking the secure vault, the PowerAuth Signature must be calculated from the final, encrypted data ("encrypt-then-sign").
<!-- end -->

#### Response 200

```json
{
    "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
    "encryptedVaultEncryptionKey": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
}
```
<!-- end -->

<!-- begin api POST /pa/v3/signature/validate -->
### Validate Signature

Validate a PowerAuth signature in the `X-PowerAuth-Authorization` HTTP header. The HTTP request can use the `GET`, `POST`, `PUT` or `DELETE` method.

The following signature types are supported:

- `possession_knowledge`
- `possession_biometry`
- `possession_knowledge_biometry`

The request body should contain data used for computing the signature.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`, `GET`, `PUT`, `DELETE` |
| Resource URI      | `/pa/v3/signature/validate`    |
<!-- end -->

#### Request

##### Signature Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`, `GET`, `PUT`, `DELETE` |
| Signature uriId   | `/pa/signature/validate`       |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request body can contain any valid JSON data:

```json
{
  "_comment": "... signed request data"
}
```

#### Response 200

```json
{
    "status": "OK"
}
```

### Response 401

```json
{
    "status": "ERROR",
    "responseObject": {
        "code": "POWERAUTH_AUTH_FAIL",
        "message": "Signature validation failed"
    }
}
```
<!-- end -->

<!-- begin api POST /pa/v3/upgrade/start -->
### Upgrade Start

Start a process to upgrade from protocol version 2, to version 3. PowerAuth Client simply receives an initial value for `CTR_DATA`, a hash-based counter.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/upgrade/start`      |
<!-- end -->

#### Request

##### Encryption Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| ECIES             | `activation, sh1="/pa/upgrade"` |

##### Encryption Header

```
X-PowerAuth-Encryption: PowerAuth ...
```

##### Body

The JSON request body before the encryption is an empty JSON:

```json
{}
```

#### Response 200

The JSON response after the decryption:

```json
{
    "ctrData": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J=="
}
```
<!-- end -->

<!-- begin api POST /pa/v3/upgrade/commit -->
### Upgrade Commit

Finish an upgrade process. In this step, the PowerAuth signature must be calculated with respecting a new, protocol V3 scheme (e.g. must use `CTR_DATA` instead of old `CTR`).

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/upgrade/commit`     |
<!-- end -->

#### Request

##### Signature Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/upgrade/commit`        |

##### Signature Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{}
```

#### Response 200

```json
{}
```
<!-- end -->

<!-- begin api POST /pa/v3/recovery/confirm -->
### Confirm Recovery

Confirm a recovery code created for a recovery postcard. The recovery code is confirmed once user receives a postcard with recovery code and PUKs.

<!-- begin remove -->
| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Resource URI      | `/pa/v3/recovery/confirm`   |
| Signature uriId   | `/pa/recovery/confirm`      |
| ECIES             | `activation, sh1="/pa/recovery/confirm"` |
<!-- end -->

#### Request

##### Signature and Encryption Parameters

| Request parameter | Value                       |
| ----------------- | --------------------------- |
| Method            | `POST`                      |
| Signature uriId   | `/pa/recovery/confirm`      |
| ECIES             | `activation, sh1="/pa/recovery/confirm"` |

##### Signature Headers

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request before an ECIES encryption:

```json
{
    "recoveryCode": "VVVVV-VVVVV-VVVVV-VTFVA"
}
```

An actual JSON request body after the encryption:

```json
{
    "ephemeralPublicKey" : "A5Iuit2vV1zgLb/ewROYGEMWxw4zjSoM2e2dO6cABY78",
    "encryptedData" : "7BzoLuLYKZrfFfhlom1zMA==",
    "mac" : "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "nonce" : "v1y015uEP5RuT2g9RS6LIw=="
}
```

#### Response 200

The JSON response before ECIES decryption:

```json
{
    "mac": "JpDckCpQ6Kh/gGCdBZQSh11x38EaU/DL2r/2BCXohMI=",
    "encryptedData": "7LK7qs+OK0cfQPZlkzl2G8z5/IZx0SHhI/BPYFhhxqE="
}
```

The JSON response after the decryption:

```json
{
    "alreadyConfirmed" : false
}
```
<!-- end -->
