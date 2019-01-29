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
- Response values encrypted with ECIES level 2 
    - `customAttributes` - Structure for application-specific data.
    
After receiving the response, PowerAuth Client decrypts both layers of response data and continues with the activation process. You can check the documentation for an [Activation](./Activation.md) for more details.


|-------------------|----------------------------|
| Method            | `POST`                     |
| Resource URI      | `/pa/v3/activation/create` |
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
    "extras": ""Any data in string format"
}
```

JSON request object before ECIES level 1 encryption:
```json
{
    "activationType": "CODE",
    "identityAttributes": {
        "code": "VVVVV-VVVVV-VVVVV-VTFVA",
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

JSON response after ECIES level 2 decryption:
```json
{
    "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
    "serverPublicKey": "NESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
    "ctrData": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J=="
}
```

## Activation status

Get the status of an activation with given activation ID. The PowerAuth Server response contains an encrypted activation status blob. More information about the format of status blob and encryption can be found in the [chapter on activation status cryptography](./Activation-Status.md).

This endpoint also returns a `customObject` object with custom application specific data. This object may be used for example to provide service specific data (current timestamp, info about service status, ...) in order to minimize number of required request in practical deployments (for example, mobile banking needs to ask for the service status data on application launch).

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/activation/status</code></td>
    </tr>
</table>

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

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/activation/remove</code></td>
    </tr>
</table>

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

The request contains:
   - `ephemeralPublicKey` - a Base64 encoded ephemeral public key which is used for response encryption using ECIES scheme.

In case the PowerAuth signature is verified correctly, the server returns a response which contains encrypted ECIES envelope:
   - `mac` - MAC signature of the response, Base64 encoded
   - `encryptedData` - data encrypted using ECIES scheme, Base64 encoded

The encrypted data payload contains following object:

```json
{
   "token_id": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "token_secret": "VqAXEhziiT27lxoqREjtcQ=="
}
```

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/token/create</code></td>
    </tr>
</table>

### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body:
```json
{
    "requestObject": {
        "ephemeralPublicKey": "AhntJuqdqTli2sOwb3GtGR7qD0jElYpVI2AlpyNGOiH4"
    }
}
```

#### Response

- Status code: `200`
- Headers
    - `Content-Type: application/json`

```json
{
    "requestObject": {
        "mac": "xvJ1Zq0mOtgvVqbspLhWMt2NJaTDZ5GkPBbcDxXRB9M=",
        "encryptedData": "6jeU9S2FeN5i+OWsTWh/iA5Tx5e9JKFW0u1D062lFsMRIQwcNJZYkPoxWXQDIHdT5OIQrxMe4+qH+pNec5HlzBacZPAy3fB3fCc25OJAoXIaBOTatVbAcsuToseNanIX3+ZNcyxIEVj16OoawPhm1w==",
    }
}
```

## Remove token

Remove a previously created token.

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/token/remove</code></td>
    </tr>
</table>

### Request

- Headers
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body:
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

```json
{
    "requestObject": {
        "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
    }
}
```

## Vault unlock

Get the vault unlock key in order to decrypt data stored in the vault, for example the original `KEY_DEVICE_PRIVATE`.

PowerAuth Client sends an authenticated request using an activation ID - authentication is carried around using the standard PowerAuth signature with at least 2 factors (2FA).

In response, PowerAuth Server sends a `KEY_ENCRYPTION_VAULT` key encrypted using `KEY_ENCRYPTION_VAULT_TRANSPORT` key associated with given counter (derived from the `KEY_TRANSPORT` master key, see the `PowerAuth Key Derivation` chapter for details).

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT_TRANSPORT)`

PowerAuth Client can later decrypt the key using the inverse mechanism:

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT_TRANSPORT)`

_Note: Both the signature calculation / validation and `KEY_ENCRYPTION_VAULT_TRANSPORT` key derivation should increase the counter `CTR`! In other words, if signature uses value of `CTR = N`, key derivation should use `CTR = N + 1`. For technical reason, the client should compute the `KEY_ENCRYPTION_VAULT_TRANSPORT` ahead - we need to assure that only server may be behind the client with a `CTR` value, not vice versa._

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/vault/unlock</code></td>
    </tr>
</table>

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body:

```json
{
    "reason": "NOT_SPECIFIED"
}
```

You can provide any "reason" for vault unlocking. Our SDKs use following states by default:

- `ADD_BIOMETRY` - call was used to enable biometric authentication.
- `FETCH_ENCRYPTION_KEY` - call was used to fetch a generic data encryption key.
- `SIGN_WITH_DEVICE_PRIVATE_KEY` - call was used to unlock device private key used for ECDSA signatures.

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

```json
    {
        "status": "OK",
        "responseObject": {
            "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
            "encryptedVaultEncryptionKey": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
        }
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

<table>
    <tr>
        <td>Method</td>
        <td><code>GET/POST/PUT/DELETE</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/v3/signature/validate</code></td>
    </tr>
</table>

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body:

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