# PowerAuth Standard RESTful API

<!-- TEMPLATE api -->

To ensure a standard behavior of various PowerAuth implementations, a fixed endpoint and request/response structure between PowerAuth Client and Intermediate Server Application is specified for the PowerAuth protocol.

Each PowerAuth implementation located on a specific base URL then has `/pa/` prefixed endpoints by convention.

<!-- begin remove -->
The following endpoints are published in PowerAuth Standard RESTful API (protocol version 4):

- [`/pa/v4/activation/create`](#initiate-activation) - Create a new activation, perform a key exchange based on activation code.
- [`/pa/v4/activation/status`](#activation-status) - Query for an activation status.
- [`/pa/v4/activation/confirm`](#activation-confirm) - Confirm activation (requires authentication).
- [`/pa/v4/activation/remove`](#activation-remove) - Remove an activation (requires authentication).
- [`/pa/v4/token/create`](#create-token) - Create a token (requires authentication and encryption).
- [`/pa/v4/token/remove`](#remove-token) - Remove a token (requires authentication).
- [`/pa/v4/vault/unlock`](#vault-unlock) - Get a key to unlock secure vault (requires authentication and encryption).
- [`/pa/v4/auth/validate`](#validate-authentication-code) - Validate an authentication code (requires authentication).
- [`/pa/v4/password/change`](#password-change) - Change password for the knowledge factor (requires authentication).
- [`/pa/v4/biometry/add`](#enable-biometry) - Enable the biometry factor (requires authentication).
- [`/pa/v4/biometry/remove`](#remove-biometry) - Remove the biometry factor (requires authentication).
- [`/pa/v4/upgrade/start`](#upgrade-start) - Start a protocol upgrade (requires authentication and encryption).
- [`/pa/v4/upgrade/confirm`](#upgrade-confirm) - Finishes a protocol upgrade (requires authentication).
- [`/pa/v4/keystore/create`](#create-new-key-pair) - Create a new temporary key pair for end-to-end encryption.
<!-- end -->

## Security Features

Before you continue, we suggest reading the [End-To-End encryption](./End-To-End-Encryption.md) and [Computing and Validating Authentication Codes](Computing-and-Validating-Authentication-Codes.md) documents, describing encryption and authentication mechanism used in the RESTful APIs.

## Content Type

All requests and responses use the JSON format. The following header needs to be set in the request:

```
Content-Type: application/json
```

## Error Handling

PowerAuth Standard RESTful API uses a unified format for error response body, accompanied with an appropriate HTTP status code. Besides the HTTP error codes that application server may return regardless of server application (such as 404 when resource is not found or 503 when server is down), the following status codes may be returned:

| Code | Description                                                           |
|------|-----------------------------------------------------------------------|
| 200  | OK response, no issues                                                |
| 400  | Issue with a request format, or issue of the business logic           |
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
The code and message are usually very generic and do not provide a lot of information. Please consult the server log for details. On the application level, use the HTTP status code to determine the type of the issue and present the appropriate message to the user.
<!-- end -->

## Activation Lifecycle API

<!-- begin api POST /pa/v4/activation/create -->
### Initiate Activation

Exchange the public keys between PowerAuth Client and PowerAuth Server.

Application activation is a process of key exchange between a PowerAuth Client and a PowerAuth Server. During this process, an "activation record" is created on the PowerAuth Server and related keys are stored on a PowerAuth Client.

<!-- begin remove -->
| Request parameter | Value                      |
|-------------------|----------------------------|
| Method            | `POST`                     |
| Resource URI      | `/pa/v4/activation/create` |
<!-- end -->

#### Request

PowerAuth Client sends the following data on the server:

- Request values encrypted with level 2 encryption:
    - `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
    - `sharedSecretRequest` - Request for deriving a shared secret.
        - `algorithm` - Cryptography algorithm suite name used for deriving the shared secret.
        - `encapsulationKeys` - List of Base-64 encoded encapsulation keys in order specified by used algorithm suite.
    - `devicePublicKeys` - Represents device public keys.
        - `ecdsa` - ECDSA device public key encoded in Base-64 encoding.
        - `mldsa` - MLDSA device public key encoded in Base-64 encoding.
    - `activationOtp` - Optional authentication OTP used for additional user authentication.
    - `platform` - User device platform, e.g. `ios`, `android`, `hw` and `unknown`.
    - `deviceInfo` - Information about the user device, e.g. `iPhone12,3`.
    - `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.
- Request encrypted with level 1 encryption:
    - `type` - Assume that standard activation is using "CODE" constant as an activation type.
    - `identityAttributes` - Contains the `ACTIVATION_CODE` value inside this map, mapped using the `code` key.
- Not encrypted values (HTTP header)
    - `applicationKey` - Represents an application with a given `APPLICATION_KEY`

PowerAuth Server decrypts both levels of encryption and returns the following data:

- Response values encrypted with level 2 encryption
    - `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
    - `sharedSecretResponse` - Response for deriving a shared secret.
        - `salt` - Salt used for the shared secret derivation encoded in Base-64 encoding.
        - `encapsulatedKeys` - List of Base-64 encoded encapsulated keys in order specified by used algorithm suite.
    - `serverPublicKeys` - Represents server public keys.
        - `ecdsa` - ECDSA server public key encoded in Base-64 encoding.
        - `mldsa` - MLDSA server public key encoded in Base-64 encoding.
    - `ctrData` - Initial value for hash-based counter.
- Response values encrypted with level 1 encryption
    - `customAttributes` - Structure for application-specific data.

After receiving the response, PowerAuth Client decrypts both layers of response data and continues with the activation process. You can check the documentation for an [Activation](./Activation.md) for more details.

##### Encryption Parameters

| Request parameter    | Value                                        |
|----------------------|----------------------------------------------|
| Encryption (level 1) | `application, sh1="/pa/generic/application"` |
| Encryption (level 2) | `application, sh1="/pa/activation"`          |

##### Encryption Headers

```
X-PowerAuth-Encryption: PowerAuth version="4.0", application_key="UNfS0VZX3JhbmRvbQ=="
```

##### Body

The JSON request object before level 2 encryption:

```json
{
  "sharedSecretRequest": {
    "algorithm": "EC_P384_ML_L5",
    "encapsulationKeys": ["NuIkMs...", "IqWwre..."]
  },
  "devicePublicKeys": {
    "ecdsa": "BE7vkE...",
    "mldsa": "MIIKMj..."
  },
  "activationName": "My iPhone",
  "activationOtp": "12345678",
  "platform": "ios",
  "deviceInfo": "iPhone12,3",
  "extras": "Any data in string format"
}
```

The JSON request object before level 1 encryption. The `activationData` field contains the previous object after the level 2 encryption:

```json
{
  "type": "CODE",
  "identityAttributes": {
    "code": "VVVVV-VVVVV-VVVVV-VTFVA"
  },
  "customAttributes": {
    "key": "value"
  },
  "activationData": {
    "temporaryKeyId" : "f4d2171c-be66-4d04-aaa3-9d828aaeb15e",
    "encryptedData" : "KWabFKLAuQCkb+lNHyMA3Xx4HplMmQ3y9wnt7FMEH9...",
    "nonce" : "KWabFKLAuQCkb+lNS3bqj2xq60Td3cYJ",
    "timestamp" : 1769422877091
  }
}
```

The actual request payload then looks like:

```json
{
  "temporaryKeyId" : "f4d2171c-be66-4d04-aaa3-9d828aaeb15e",
  "encryptedData" : "H1nYcs4WqSC8/Vo3lZYd/wHAb8qC1yHOlzjQlkUOqmu1...",
  "nonce" : "H1nYcs4WqSC8/Vo3M0VBe+RyQ1FGlw1l",
  "timestamp" : 1769422877113
}
```

#### Response 200

The JSON response (before any decryption) is the following:

```json
{
  "encryptedData" : "M0VBe+RyQ1FGlw1lhz7SFBEC8d7gbglG+zwq11kpljEC...",
  "timestamp" : 1769422877163
}
```

The JSON response after level 1 decryption unwraps to:

```json
{
  "customAttributes": {
    "any-key": "any-value"
  },
  "activationData": {
    "encryptedData" : "S3bqj2xq60Td3cYJ1x8dEjdw+6v5k74QZGNNBFunuC...",
    "timestamp" : 1769422877150
  }
}
```

The `activationData` contains an encrypted level 2 response. So, the JSON response after level 2 decryption is the following:

```json
{
  "sharedSecretResponse" : {
    "salt" : "GwHlUc4dXvDobaBlInu8gDAQd5fIZiPyYVYt69YUjYo=",
    "encapsulatedKeys" : [
      "BIJ8Eoxi2tgxQetJ5h+Eee6K/NGjQdshSK+pul1mOUn9K++xIWU39SkcUc..."
    ]
  },
  "serverPublicKeys" : {
    "ecdsa" : "BE7vkE7d7mFNNaKthB40Z3/iCWcCWo33zZnbZODy3UsdzemEia...",
    "mldsa" : "MIIKMjALBglghkgBZQMEAxMDggohAB7aX4ahNmri8c9FuqspYT..."
  },
  "activationId" : "3c816946-2df7-4804-989c-31a87aa494bc",
  "ctrData" : "0D8cZ7KinStnSo5XCHmVQTkWJz5UMl5bPAPlV5GXxKc="
}
```

<!-- end -->

<!-- begin api POST /pa/v4/activation/status -->
### Activation Status

Get the status of an activation with given activation ID. The PowerAuth Server response contains an activation status blob. The endpoint is encrypted using standard PowerAuth end-to-end encryption. More information about the format of status blob and encryption can be found in the [chapter on activation status cryptography](./Activation-Status.md).

This endpoint also returns a `customObject` object with custom application specific data. This object may be used for example to provide service specific data (current timestamp, info about service status, ...) in order to minimize number of required request in practical deployments (for example, mobile banking needs to ask for the service status data on application launch).

<!-- begin remove -->
| Request parameter | Value                      |
|-------------------|----------------------------|
| Method            | `POST`                     |
| Resource URI      | `/pa/v4/activation/status` |
<!-- end -->

#### Request

Activation ID and encryption context are provided via standard PowerAuth request context (authentication headers and parameters). This endpoint does not use a JSON request body.

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "activationStatus": "19gyYaW5ZhdGl...",
    "customObject": {
      "_comment": "Any object data, such as timestamp, service status info, etc."
    }
  }
}
```
<!-- end -->

<!-- begin api POST /pa/v4/activation/confirm -->
### Activation Confirm

Confirm an activation after it was created on mobile device. This call finalizes the activation and may optionally enable biometry.

The endpoint is authenticated using standard PowerAuth authentication with `POSSESSION_KNOWLEDGE` 2FA authentication.

<!-- begin remove -->
| Request parameter | Value                       |
|-------------------|-----------------------------|
| Method            | `POST`                      |
| Resource URI      | `/pa/v4/activation/confirm` |
<!-- end -->

#### Request

##### Authentication Parameters

| Request parameter    | Value                    |
|----------------------|--------------------------|
| Method               | `POST`                   |
| Authentication uriId | `/pa/activation/confirm` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{
  "requestObject": {
    "enableBiometry": true
  }
}
```

The `enableBiometry` flag is optional. If set to true, the server enables the default biometric factor.

#### Response 200

```json
{
  "status": "OK"
}
```
<!-- end -->

<!-- begin api POST /pa/v4/activation/remove -->
### Activation Remove

Remove an activation with given ID, set the activation status to `REMOVED`. Activation can be removed only after successful verification of the signature.

PowerAuth Client sends an authenticated request using an activation ID. Authentication is carried around using the standard PowerAuth authentication code with at least two factors (2FA).

<!-- begin remove -->
| Request parameter | Value                      |
|-------------------|----------------------------|
| Method            | `POST`                     |
| Resource URI      | `/pa/v4/activation/remove` |
<!-- end -->

#### Request

##### Authentication Parameters

To construct the PowerAuth Client authentication code, use the `POST` method and `/pa/activation/remove` as URI identifier.

| Request parameter    | Value                   |
|----------------------|-------------------------|
| Method               | `POST`                  |
| Authentication uriId | `/pa/activation/remove` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

Any, the value is ignored but must match the authorization header.

#### Response 200

```json
{
  "status": "OK",
  "responseObject": {
    "activationId": "3c816946-2df7-4804-989c-31a87aa494bc"
  }
}
```
<!-- end -->

## Token Lifecycle API

<!-- begin api POST /pa/v4/token/create -->
### Create Token

Create a static token which can be used for repeated requests to data resources which support token based authentication.

<!-- begin remove -->
| Request parameter | Value                 |
|-------------------|-----------------------|
| Method            | `POST`                |
| Resource URI      | `/pa/v4/token/create` |
<!-- end -->

#### Request

##### Signature and Encryption Parameters

| Request parameter | Value                                |
|-------------------|--------------------------------------|
| Method            | `POST`                               |
| Signature uriId   | `/pa/token/create`                   |
| Encryption        | `activation, sh1="/pa/token/create"` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request object, before encryption (an empty JSON object):

```json
{}
```

Actual JSON request body, after the encryption:

```json
{
  "temporaryKeyId" : "d9b2d251-ac60-4c53-a2f4-a5281e73cd36",
  "encryptedData" : "sHOxELRW3GHXrmfOkQmxLNU+2HCA8kGTt1KcLPbrFUaC...",
  "nonce" : "sHOxELRW3GHXrmfOq/u/LMj1SI9OwEx8",
  "timestamp" : 1769424304514
}
```

<!-- begin box warning -->
When creating a new token, the PowerAuth authentication code must be calculated from the final encrypted data ("encrypt-then-authenticate").
<!-- end -->

#### Response 200

The JSON response before the decryption:

```json
{
  "encryptedData" : "l7f9qtwZ9v0uZN6Kzfxwy32hE3TQ4m1ALwuYHMbBI5cS...",
  "timestamp" : 1769424474562
}
```

The JSON object after the decryption:

```json
{
  "status": "OK",
  "responseObject": {
    "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",
    "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
  }
}
```
<!-- end -->

<!-- begin api POST /pa/v4/token/remove -->
### Remove Token

Remove a previously created token.

<!-- begin remove -->
| Request parameter | Value                 |
|-------------------|-----------------------|
| Method            | `POST`                |
| Resource URI      | `/pa/v4/token/remove` |
<!-- end -->

#### Request

##### Authentication Parameters

| Request parameter    | Value              |
|----------------------|--------------------|
| Method               | `POST`             |
| Authentication uriId | `/pa/token/remove` |

##### Authorization Header

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
{
  "status": "OK",
  "responseObject": {
    "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
  }
}
```
<!-- end -->

## Secure Vault API

<!-- begin api POST /pa/v4/vault/unlock -->
### Vault Unlock

Get the vault unlock key to decrypt data stored in the vault, for example the `KEK_DEVICE_PRIVATE`.

<!-- begin remove -->
| Request parameter | Value                 |
|-------------------|-----------------------|
| Method            | `POST`                |
| Resource URI      | `/pa/v4/vault/unlock` |
<!-- end -->

#### Request

PowerAuth Client sends an encrypted and authenticated request using an activation ID. The authentication is carried around using the standard PowerAuth authentication code with at least two factors (2FA). The combination of "possession" and "knowledge" factors is supported by default, the biometry may be explicitly allowed by a particular deployment.

In response, PowerAuth Server sends the requested encryption key.

<!-- begin box info -->
The protection of the vault encryption key transmission is done using standard PowerAuth end-to-end encryption.
<!-- end -->

The following keys can be requested:
- `KEK_DEVICE_PRIVATE` - key encryption key for encrypting the device private key in vault unlock
- `KDK_APP_VAULT_2FA` - key encryption key for vault provided after any 2FA authorization
- `KDK_APP_VAULT_KNOWLEDGE` - key encryption key for vault used after knowledge-based 2FA authorization

##### Authentication and Encryption Parameters

| Request parameter | Value                                |
|-------------------|--------------------------------------|
| Method            | `POST`                               |
| Signature uriId   | `/pa/vault/unlock`                   |
| Encryption        | `activation, sh1="/pa/vault/unlock"` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request before encryption:

```json
{
  "keyIdentifier": "KEK_DEVICE_PRIVATE",
  "reason": "SIGN_WITH_DEVICE_PRIVATE_KEY"
}
```

You can provide the following reasons for a vault unlock:

- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for asymmetric signatures.

An actual JSON request body after the encryption is the following:

```json
{
  "temporaryKeyId" : "5c283065-ce1e-4c81-a3e2-dc058eadd94b",
  "encryptedData" : "RDBNaXa1pTmUqR76MbkCFYmc1dvhDdPV8DkiQ4rG4a7HmP8E2hxnIsMtMLgU8VqiryZRtDCtSUtBtcmgraFQ2ya1Er7tMDvO69WiY8SYgSVoCA==",
  "nonce" : "RDBNaXa1pTmUqR764aUOIrgTjV4Fw0iF",
  "timestamp" : 1769425681453
}
```

<!-- begin box warning -->
When unlocking the secure vault, the PowerAuth authentication code must be calculated from the final, encrypted data ("encrypt-then-authenticate").
<!-- end -->

#### Response 200

```json
{
  "encryptedData": "...",
  "timestamp": 1769425681453
}
```

After decryption:

```json
{
  "vaultEncryptionKey" : "GJWlId+P6TrIMcZ2Z6P855sf7EsqBfJZBxJfiQiXsHc="
}
```
<!-- end -->

## Authentication API

<!-- begin api POST /pa/v4/auth/validate -->
### Validate Authentication Code

Validate a PowerAuth signature in the `X-PowerAuth-Authorization` HTTP header. The HTTP request can use the `GET`, `POST`, `PUT` or `DELETE` method.

The following authentication code types are supported:

- `possession_knowledge`
- `possession_biometry`
- `possession_knowledge_biometry`

The request body should contain data used for computing the authentication code.

<!-- begin remove -->
| Request parameter | Value                          |
|-------------------|--------------------------------|
| Method            | `POST`, `GET`, `PUT`, `DELETE` |
| Resource URI      | `/pa/v4/auth/validate`         |
<!-- end -->

#### Request

##### Authentication Code Parameters

| Request parameter | Value                          |
|-------------------|--------------------------------|
| Method            | `POST`, `GET`, `PUT`, `DELETE` |
| Signature uriId   | `/pa/auth/validate`            |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request body can contain any valid JSON data:

```json
{
  "_comment": "... authenticated request data"
}
```

#### Response 200

```json
{
  "status": "OK"
}
```

#### Response 401

```json
{
  "status": "ERROR",
  "responseObject": {
    "code": "POWERAUTH_AUTH_FAIL",
    "message": "Authentication failed"
  }
}
```
<!-- end -->


<!-- begin api POST /pa/v4/password/change -->
### Password Change

Change password (PIN) for the knowledge factor.

#### Request

Authenticated request using standard PowerAuth authentication using `POSSESSION_KNOWLEDGE` 2FA authentication.

##### Authentication Parameters

| Request parameter    | Value                 |
|----------------------|-----------------------|
| Method               | `POST`                |
| Authentication uriId | `/pa/password/change` |

The request is encrypted using standard end-to-end encryption in activation scope, `sh1="/pa/password/change"`.
 
##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{
  "temporaryKeyId" : "5c283065-ce1e-4c81-a3e2-dc058eadd94b",
  "encryptedData" : "...",
  "nonce" : "RDBNaXa1pTmUqR764aUOIrgTjV4Fw0iF",
  "timestamp" : 1769425681453
}
```

#### Response 200

```json
{
  "encryptedData": "...",
  "timestamp": 1769425681453
}
```
<!-- end -->

<!-- begin api POST /pa/v4/biometry/add -->
### Enable Biometry

Enable the dynamic biometry factor.

#### Request

Authenticated request using standard PowerAuth authentication using `POSSESSION_KNOWLEDGE` 2FA authentication.

##### Authentication Parameters

| Request parameter    | Value              |
|----------------------|--------------------|
| Method               | `POST`             |
| Authentication uriId | `/pa/biometry/add` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{
  "temporaryKeyId" : "5c283065-ce1e-4c81-a3e2-dc058eadd94b",
  "encryptedData" : "...",
  "nonce" : "RDBNaXa1pTmUqR764aUOIrgTjV4Fw0iF",
  "timestamp" : 1769425681453
}
```

#### Response 200

```json
{
  "encryptedData": "...",
  "timestamp": 1769425681453
}
```
<!-- end -->

<!-- begin api POST /pa/v4/biometry/remove -->
### Remove Biometry

Disable the dynamic biometry factor.

#### Request

Authenticated request using standard PowerAuth authentication using `POSSESSION` 1FA authentication.

##### Authentication Parameters

| Request parameter    | Value                 |
|----------------------|-----------------------|
| Method               | `POST`                |
| Authentication uriId | `/pa/biometry/remove` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

#### Request

This endpoint does not use a request body.

#### Response 200

```json
{
  "status": "OK"
}
```
<!-- end -->

## Protocol Upgrade API

<!-- begin api POST /pa/v4/upgrade/start -->
### Upgrade Start

Start a process to upgrade from protocol version 3, to version 4. The request is encrypted and authenticated using the `POSSESSION_KNOWLEDGE` 2FA authentication.

<!-- begin remove -->
| Request parameter | Value                  |
|-------------------|------------------------|
| Method            | `POST`                 |
| Resource URI      | `/pa/v4/upgrade/start` |
<!-- end -->

#### Request

##### Encryption and Authentication Parameters

| Request parameter    | Value                           |
|----------------------|---------------------------------|
| Encryption           | `activation, sh1="/pa/upgrade"` |
| Authentication uriId | `/pa/upgrade/start`             |

##### Encryption Header

```
X-PowerAuth-Encryption: PowerAuth ...
```

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

The JSON request body before the encryption has the following format:

```json
{
  "sharedSecretRequest": {
    "algorithm": "EC_P384_ML_L5",
    "encapsulationKeys": [
      "NuIkMs...",
      "IqWwre..."
    ]
  },
  "devicePublicKeys": {
    "ecdsa": "BE7vkE...",
    "mldsa": "MIIKMj..."
  },
  "enableBiometry": true
}
```

#### Response 200

The JSON response after the decryption:

```json
{
  "sharedSecretResponse" : {
    "salt" : "GwHlUc4dXvDobaBlInu8gDAQd5fIZiPyYVYt69YUjYo=",
    "encapsulatedKeys" : [
      "BIJ8Eoxi2tgxQetJ5h+Eee6K/NGjQdshSK+pul1mOUn9K++xIWU39SkcUc..."
    ]
  },
  "serverPublicKeys" : {
    "ecdsa" : "BE7vkE7d7mFNNaKthB40Z3/iCWcCWo33zZnbZODy3UsdzemEia...",
    "mldsa" : "MIIKMjALBglghkgBZQMEAxMDggohAB7aX4ahNmri8c9FuqspYT..."
  },
  "ctrData" : "8XTmuC+RCSjqaz6uJMZ1jWBdSLDA4AOZaBYD9PpzOk4="
}
```
<!-- end -->

<!-- begin api POST /pa/v4/upgrade/confirm -->
### Upgrade Confirm

Finish an upgrade process.

<!-- begin remove -->
| Request parameter | Value                    |
|-------------------|--------------------------|
| Method            | `POST`                   |
| Resource URI      | `/pa/v4/upgrade/confirm` |
<!-- end -->

#### Request

##### Authentication Parameters

| Request parameter    | Value                 |
|----------------------|-----------------------|
| Method               | `POST`                |
| Authentication uriId | `/pa/upgrade/confirm` |

##### Authorization Header

```
X-PowerAuth-Authorization: PowerAuth ...
```

##### Body

```json
{}
```

#### Response 200

```json
{
  "status": "OK"
}
```
<!-- end -->

## Temporary Keys API

<!-- begin api POST /pa/v4/keystore/create -->
### Create New Key Pair

Create a new temporary key pair with either application or activation scope, and obtain the temporary public for subsequent encryption.

<!-- begin remove -->
| Request parameter | Value                    |
|-------------------|--------------------------|
| Method            | `POST`                   |
| Resource URI      | `/pa/v4/keystore/create` |
<!-- end -->

#### Request

##### Body

The JSON request contains an encoded JWT payload (signed with `HS384`) in a standard request envelope:

```json
{
  "requestObject": {
    "jwt": "..."
  }
}
```

The decoded content of the JWT payload is:

```json
{
  "applicationKey" : "...",
  "activationId" : "...",
  "challenge" : "..."
}
```

If the `activationId` is present (and represents an existing activation), the payload represents request for **activation scoped** temporary public key. Otherwise, the payload represents request for **application scoped** temporary public key. The scope determines how the JWT is signed. In both cases, the JWT is signed with standard `HS384` algorithm, with the following secret key:

- Application scope: Secret key is derived using the SHA3-256 algorithm using application secret `APP_SECRET`.
- Activation scope: Secret key is derived using the KMAC-256 algorithm using application secret `APP_SECRET` and key `KEY_E2EE_SHARED_INFO2`.

#### Response 200

The JSON response contains an encoded JWT payload (signed with `ES384` and optionally with `MLDSA`) in a standard request envelope:

```json
{
  "status": "OK",
  "responseObject": {
    "jwt": "..."
  }
}
```

The decoded content of the JWT payload is:

```json
{
  "sub": "...",
  "applicationKey" : "...",
  "activationId" : "...",
  "challenge" : "...",
  "publicKey": "...",
  "iat": "...",
  "exp": "...",
  "iat_ms": "...",
  "exp_ms": "..."
}
```

- The `sub` claim represents temporary key ID.
- The `applicationKey`, `activationId` and `challenge` claims are the same as in the request, so that the client can validate the response from the server not only for correct signature, but also to ensure the response is related to the issued request.
- The `publicKey` claim represents Base64 encoded temporary public key.
- The `iat` and `exp` attributes are standard claims representing timestamp of JWT issue and expiration timestamp. To provide millisecond precision, they are augmented with `iat_ms` and `exp_ms` claims.

The issued public key can be related to either application or activation scope, based on the presence of `activationId` (see the request description for the details). In both cases, the JWT with the public key is signed using `ES384` algorithm (optionally also with `MLDSA`), and the scope determines what key is used:

- Application scope: Private key is the application-specific master server private key `KEY_SERVER_MASTER_PRIVATE`.
- Activation scope: Private key is the activation-specific server private key `KEY_SERVER_PRIVATE`.

<!-- end -->