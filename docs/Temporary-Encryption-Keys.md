# Temporary Encryption Keys

To provide better resilience of encryption via advanced features, such as forward secrecy, PowerAuth protocol supports temporary encryption keys (since protocol version 3.3). The idea is that the keys embedded in the mobile app (`KEY_SERVER_*_PUBLIC`) and device specific server public keys (`KEY_DEVICE_*_PUBLIC`) are only used for signature verification, serving as trust store on the client for data signed on the server.

Temporary encryption keys are created on the server side via PowerAuth Standard RESTful API. The server keeps the temporary encryption key that can be used in a standard end-to-end encryption.

The client can request two scopes of temporary encryption keys:

- *Application scope* - the encryption key was obtained based on the trust created for the application specific key pair (master server keypair).
- *Activation scope* - the encryption key was obtained based on the trust created for the specific activation and it's server key pair (server keypair).

You can see more information about specific request payloads in [Standard RESTful API documentation](./Standard-RESTful-API.md#temporary-keys-api).

## Application Scope

The client sends request in the form of JWT, specifying two parameters:

- `applicationKey` - key `APP_KEY` associated with the application version
- `challenge` - random challenge, used as a request reference
- `sharedSecretRequest` - Request for deriving a shared secret.
  - `algorithm` - Cryptography algorithm suite name used for deriving the shared secret.
  - `encapsulationKeys` - List of Base-64 encoded encapsulation keys in order specified by used algorithm suite.

The JWT is signed using `HS384` with signing key `KEY_MAC_GET_APP_TEMP_KEY`.

The server then takes the request, generates a temporary encryption key associated with the application key, and sends the JWT response signed with `ES384` using `KEY_SERVER_ECDSA_384_PRIVATE` (optionally signed also with `MLDSA` algorithm based on used algorithm suite). The JWT response contains:

- `sub` - identifier of the key
- `applicationKey` - back reference to the original data
- `challenge` - back reference to the original data
- `sharedSecretResponse` - Response for deriving a shared secret.
  - `salt` - Salt used for the shared secret derivation encoded in Base-64 encoding.
  - `encapsulatedKeys` - List of Base-64 encoded encapsulated keys in order specified by used algorithm suite.
- `iat` / `iat_ms` - temporary key pair issuance timestamp
- `exp` / `exp_ms` - temporary key pair expiration timestamp

The client app should process the response by verifying the signature and checking that the application key and challenge match the expected value. Then, the client app can accept the temporary key.

## Activation Scope

The client sends request in the form of JWT, specifying three parameters:

- `applicationKey` - key `APP_KEY` associated with the application version
- `activationId` - identifier of the specific PowerAuth activation
- `challenge` - random challenge, used as a request reference
- `sharedSecretRequest` - Request for deriving a shared secret.
  - `algorithm` - Cryptography algorithm suite name used for deriving the shared secret.
  - `encapsulationKeys` - List of Base-64 encoded encapsulation keys in order specified by used algorithm suite.

The JWT is signed using `HS384` with signing key `KEY_MAC_GET_ACT_TEMP_KEY`.

The server then takes the request, generates a temporary key associated with the application key and activation ID, and sends the JWT response signed with `ES384` using `KEY_SERVER_PRIVATE` (optionally signed also with `MLDSA` algorithm based on used algorithm suite). The JWT response contains:

- `sub` - identifier of the key
- `applicationKey` - back reference to the original data
- `activationId` - back reference to the original data
- `challenge` - back reference to the original data
- `sharedSecretResponse` - Response for deriving a shared secret.
  - `salt` - Salt used for the shared secret derivation encoded in Base-64 encoding.
  - `encapsulatedKeys` - List of Base-64 encoded encapsulated keys in order specified by used algorithm suite.
- `iat` / `iat_ms` - temporary key pair issuance timestamp
- `exp` / `exp_ms` - temporary key pair expiration timestamp

The client app should process the response by verifying the signature and checking that the application key, activation ID and challenge match the expected value. Then, the client app can accept the public key with given key identifier.

## Impacted Use-Cases

Besides [End-to-End Encryption](./End-To-End-Encryption.md) itself, the introduction of temporary encryption key impacts all use-cases that implicitly rely on data encryption, such as:

- New activations (using all supported methods)
- Obtaining and changing activation name from the mobile app
- Secure Vault
- MAC-based Tokens
- Obtaining User Info
- Protocol upgrade

## JWS Signatures used During Temporary Key Establishment

We adopt [RFC 7515 - JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1) for the general serialization format for the digital signatures. For example:

```json
{
    "payload" : "<payload contents>",
    "signatures" : [
        {
            "protected" : "<integrity-protected header 1 contents>",
            "signature" : "<signature 1 contents>"
        },
        {
            "protected" : "<integrity-protected header N contents>",
            "signature" : "<signature N contents>"
        }
    ]
}
```

This signature JSON format is used in the temporary key response payload.

### Signing in EC_P384 Algorithm Suite

For EC_P384 algorithm, ECDSA with P-384 and SHA-384 is used for the data signing. In this case, the signatures array contains only one object:

```json
[
    {
        "protected" : "eyJhbGciOiJFUzM4NCJ9",
        "signature" : "BASE64-ECDSA-signature"
    }
]
```

> Be aware that the SHA-384 is used as hash, despite the fact we would like to adopt SHA-3 family of hashes in our protocol.

#### Key selection

| Scope               | Who signs     | Sign with                     | Verify with                  |
|---------------------|---------------|-------------------------------|------------------------------|
| Application         | Server        | KEY_MASTER_ECDSA_P384_PRIVATE | KEY_MASTER_ECDSA_P384_PUBLIC |
| Activation          | Server        | KEY_SERVER_ECDSA_P384_PRIVATE | KEY_SERVER_ECDSA_P384_PUBLIC |
| Activation          | Client        | KEY_DEVICE_ECDSA_P384_PRIVATE | KEY_DEVICE_ECDSA_P384_PUBLIC |

### Signing in EC_P384_ML_L3 Algorithm Suite

For `EC_P384_ML_L3` algorithm suits, we use both ECDSA with P-384 and SHA-384 and ML-DSA for the data signing. In this case, the signatures array contains two objects:

```json
[
    {
        "protected" : "eyJhbGciOiJFUzM4NCJ9",
        "signature" : "BASE64-ECDSA-signature"
    },
    {
        "protected" : "eyJhbGciOiJNTC1EU0EtNjUifQ==",
        "signature" : "BASE64-ML-DSA-signature"
    }
]
```

#### Key selection

| Scope               | Algorithm | Who signs | Sign with                     | Who verifies | Verify with                  |
|---------------------|-----------|-----------|-------------------------------|--------------|------------------------------|
| Application         | ECDSA     | Server    | KEY_MASTER_ECDSA_P384_PRIVATE | Client       | KEY_MASTER_ECDSA_P384_PUBLIC |
| Application         | MLDSA     | Server    | KEY_MASTER_MLDSA65_PRIVATE    | Client       | KEY_MASTER_MLDSA65_PUBLIC    |
| Activation          | ECDSA     | Server    | KEY_SERVER_ECDSA_P384_PRIVATE | Client       | KEY_SERVER_ECDSA_P384_PUBLIC |
| Activation          | MLDSA     | Server    | KEY_SERVER_MLDSA65_PRIVATE    | Client       | KEY_SERVER_MLDSA65_PUBLIC    |
| Activation          | ECDSA     | Client    | KEY_DEVICE_ECDSA_P384_PRIVATE | Server       | KEY_DEVICE_ECDSA_P384_PUBLIC |
| Activation          | MLDSA     | Client    | KEY_DEVICE_MLDSA65_PRIVATE    | Server       | KEY_DEVICE_MLDSA65_PUBLIC    |

### Signing in EC_P384_ML_L5 Algorithm Suite

For `EC_P384_ML_L5` algorithm suite, we use both ECDSA with P-384 and SHA-384 and ML-DSA-87 for the data signing. In this case, the signatures array contains two objects:

```json
[
    {
        "protected" : "eyJhbGciOiJFUzM4NCJ9",
        "signature" : "BASE64-ECDSA-signature"
    },
    {
        "protected" : "eyJhbGciOiJNTC1EU0EtODcifQ",
        "signature" : "BASE64-ML-DSA-signature"
    }
]
```

#### Key selection

| Scope               | Algorithm | Who signs | Sign with                     | Who verifies | Verify with                  |
|---------------------|-----------|-----------|-------------------------------|--------------|------------------------------|
| Application         | ECDSA     | Server    | KEY_MASTER_ECDSA_P384_PRIVATE | Client       | KEY_MASTER_ECDSA_P384_PUBLIC |
| Application         | MLDSA     | Server    | KEY_MASTER_MLDSA87_PRIVATE    | Client       | KEY_MASTER_MLDSA87_PUBLIC    |
| Activation          | ECDSA     | Server    | KEY_SERVER_ECDSA_P384_PRIVATE | Client       | KEY_SERVER_ECDSA_P384_PUBLIC |
| Activation          | MLDSA     | Server    | KEY_SERVER_MLDSA87_PRIVATE    | Client       | KEY_SERVER_MLDSA87_PUBLIC    |
| Activation          | ECDSA     | Client    | KEY_DEVICE_ECDSA_P384_PRIVATE | Server       | KEY_DEVICE_ECDSA_P384_PUBLIC |
| Activation          | MLDSA     | Client    | KEY_DEVICE_MLDSA87_PRIVATE    | Server       | KEY_DEVICE_MLDSA87_PUBLIC    |