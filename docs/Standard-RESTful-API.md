# PowerAuth Standard RESTful API

In order to assure a standard behavior of various PowerAuth implementations, fixed endpoint and request/response structure between PowerAuth Client and Intermediate Server Application is specified for the key exchange algorithm.

While the PowerAuth Client technically communicates with an Intermediate Server Application, all response data are actually built in PowerAuth Server and Intermediate Server Application just forwards data back and forth. Therefore, we will further assume that the phrase "PowerAuth Server responds to PowerAuth Client" is a shortcut for "Intermediate Server Application requests a response from PowerAuth Server and forwards the response to PowerAuth Client".

Each PowerAuth implementation that is located on a specific base URL then has `/pa/` prefixed endpoints by convention.

Following endpoints are published in PowerAuth Standard RESTful API:

- [`/pa/activation/create`](#initiate-activation) - Create a new activation, perform a key exchange based on short activation ID.
- [`/pa/activation/status`](#activation-status) - Query for an activation status.
- [`/pa/activation/remove`](#activation-remove) - Remove an activation (requires authentication).
- [`/pa/token/create`](#create-token) - Create a token (requires authentication).
- [`/pa/token/remove`](#remove-token) - Remove a token (requires authentication).
- [`/pa/vault/unlock`](#vault-unlock) - Get a key to unlock secure vault (requires authentication).
- [`/pa/signature/validate`](#validate-signature) - Validate a signature (requires authentication).

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

- `activationIdShort` - Represents an `ACTIVATION_ID_SHORT` value (first half of an activation code).
- `applicationKey` - Represents an application with a given `APPLICATION_KEY` which should be entitled to complete the activation.
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `ephemeralPublicKey` - A technical component for AES encryption - a public component of the on-the-fly generated key pair.
- `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
- `applicationSignature` - Signature using an application secret, to prove that the activation was completed using a given application.
    - `SecretKey signatureKey = KeyConversion.secretKeyFromBytes(Base64.decode(APPLICATION_SECRET))`
    - `byte[] applicationSignature = Mac.hmacSha256(signatureKey, activationIdShort + "&" + Base64.encode(activationNonce) + "&" + Base64.encode(encryptedDevicePublicKey) + "&" + applicationKey)`
- `encryptedDevicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC` AES encrypted with `ACTIVATION_OTP`.
    - `byte[] encryptedDevicePublicKey = AES.encrypt(KEY_DEVICE_PUBLIC, activationNonce, ACTIVATION_OTP)`
- `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.

PowerAuth Server verifies the `applicationSignature` and if it matches the expected value, it responds with an following data:

- `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `ephemeralPublicKey` - A technical component for AES encryption - a public component of the on-the-fly generated key pair.
- `encryptedServerPublicKey` - Encrypted public key `KEY_SERVER_PUBLIC` of the server.
    - `SharedKey EPH_KEY = ECDH.phase(ephemeralPrivateKey, KEY_DEVICE_PUBLIC)`
    - `byte[] encryptedServerPublicKey = AES.encrypt(AES.encrypt(KEY_SERVER_PUBLIC, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`
- `serverDataSignature` - Signature of the server data - concatenated `activationId` bytes and `encryptedServerPublicKey`.
    - `byte[] activationData = ByteUtils.concat(activationId.getBytes("UTF-8"), encryptedServerPublicKey)`
    - `byte[] serverDataSignature = ECDSA.sign(activationData, KEY_SERVER_MASTER_PRIVATE)`

After receiving the response, PowerAuth Client verifies `severDataSignature` using server's public master key `KEY_SERVER_MASTER_PUBLIC` and if the signature is OK, it decrypts server public key using it's private master key `KEY_DEVICE_PRIVATE` and `ACTIVATION_OTP`.

- `byte[] activationData = ByteUtils.concat(activationId.getBytes("UTF-8"), encryptedServerPublicKey)`
- `signatureOK = ECDSA.verify(activationData, serverDataSignature, KEY_SERVER_MASTER_PUBLIC)`
- `EPH_KEY = ECDH.phase(KEY_DEVICE_PRIVATE, ephemeralPublicKey)`
- `serverPublicKey = AES.decrypt(AES.decrypt(encryptedServerPublicKey, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`

Then, PowerAuth Client deduces `KEY_MASTER_SECRET`:

- `KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE, serverPublicKey)`

After that, it proceeds with key derivation. See a separate chapter "PowerAuth Key Derivation" for details.

<table>
    <tr>
        <td>Method</td>
        <td><code>POST</code></td>
    </tr>
    <tr>
        <td>Resource URI</td>
        <td><code>/pa/activation/create</code></td>
    </tr>
</table>

### Request

- Headers:
    - `Content-Type: application/json`

```json
{
    "requestObject": {
        "activationIdShort": "XDA57-24TBC",
        "applicationKey": "UNfS0VZX3JhbmRvbQ==",
        "activationNonce": "hbmRvbQRUNESF9QVUJMSUNfS0VZX3J==",
        "ephemeralPublicKey": "RvbQSF9QRUNEVUJMSUNfS0VZX3Jhbm==",
        "activationName": "My iPhone",
        "applicationSignature": "SF9QRUNEVUJMSUNfS0VZX3JhbmRvbQ==",
        "encryptedDevicePublicKey": "RUNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
        "extras": "Any data in any format (XML, JSON, ...) for application specific purposes"
    }
}
```

### Response

- Status Code: `200`
- Headers:
    - `Content-Type: application/json`

```json
{
    "status": "OK",
    "responseObject": {
        "activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
        "activationNonce": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J==",
        "ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
        "encryptedServerPublicKey": "NESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
        "serverDataSignature": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
    }
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
        <td><code>/pa/activation/status</code></td>
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
        <td><code>/pa/activation/remove</code></td>
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
        <td><code>/pa/token/create</code></td>
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
        <td><code>/pa/token/remove</code></td>
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
        <td><code>/pa/vault/unlock</code></td>
    </tr>
</table>

### Request

- Headers:
    - `Content-Type: application/json`
    - `X-PowerAuth-Authorization: PowerAuth ...`
- Body:

```json
{
    "requestObject": {
        "reason": "NOT_SPECIFIED"
    }
}
```

You can provide any "reason" for vault unlocking. Our SDKs use following states by default:

- `PASSWORD_VALIDATE` - call was used to simply validate a password.
- `PASSWORD_CHANGE` - call was used to validate a password because of a password change.
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
        <td><code>/pa/signature/validate</code></td>
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