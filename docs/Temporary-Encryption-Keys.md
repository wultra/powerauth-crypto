# Temporary Encryption Keys

To provide better resilience of encryption via advanced features, such as forward secrecy, PowerAuth protocol supports temporary encryption keys (since protocol version 3.3). The idea is that the keys embedded in the mobile app (`KEY_SERVER_MASTER_PUBLIC`) and device specific server public key (`KEY_SERVER_PUBLIC`) are only used for signature verification, serving as trust store on the client for data signed on the server.

Temporary encryption keys are created on the server side via PowerAuth Standard RESTful API. The server keeps the temporary encryption key pair and the client receives a public key, that can be used in a standard ECIES encryption.

The client can request two scopes of temporary encryption keys:

- *Application scope* - the encryption key pair was obtained based on the trust created for the application specific key pair (master server keypair).
- *Activation scope* - the encryption key pair was obtained based on the trust created for the specific activation and it's server key pair (server keypair).

You can see more information about specific request payloads in [Standard RESTful API documentation](./Standard-RESTful-API.md#temporary-keys-api).

## Application Scope

The client sends request in the form of JWT, specifying two parameters:

- `applicationKey` - key `APP_KEY` associated with the application version
- `challenge` - random challenge, used as a request reference

The JWT is signed using `HS256` with the "application secret" (`APP_SECRET`) as the signing key.

The server then takes the request, generates a random temporary encryption key pair associated with the application key, and sends the JWT response signed with `ES256` using `KEY_SERVER_MASTER_PRIVATE`. The JWT response contains:

- `sub` - identifier of the key
- `applicationKey` - back reference to the original data
- `challenge` - back reference to the original data
- `publicKey` - temporary encryption public key
- `iat` / `iat_ms` - temporary key pair issuance timestamp
- `exp` / `exp_ms` - temporary key pair expiration timestamp

The client app should process the response by verifying the signature and checking that the application key and challenge match the expected value. Then, the client app can accept the public key with given key identifier.

## Activation Scope

The client sends request in the form of JWT, specifying three parameters:

- `applicationKey` - key `APP_KEY` associated with the application version
- `activationId` - identifier of the specific PowerAuth activation
- `challenge` - random challenge, used as a request reference

The JWT is signed using `HS256` with the key derived from "application secret" (`APP_SECRET`) and transport key (`KEY_TRANSPORT`) as the signing key:

```
JWT_SIGN_KEY = KDF_INTERNAL.derive(KEY_TRANSPORT, APP_SECRET)
```

The server then takes the request, generates a random temporary encryption key pair associated with the application key and activation ID, and sends the JWT response signed with `ES256` using `KEY_SERVER_PRIVATE`. The JWT response contains:

- `sub` - identifier of the key
- `applicationKey` - back reference to the original data
- `activationId` - back reference to the original data
- `challenge` - back reference to the original data
- `publicKey` - temporary encryption public key
- `iat` / `iat_ms` - temporary key pair issuance timestamp
- `exp` / `exp_ms` - temporary key pair expiration timestamp

The client app should process the response by verifying the signature and checking that the application key, activation ID and challenge match the expected value. Then, the client app can accept the public key with given key identifier.

## Impacted Use-Cases

Besides [End-to-End Encryption](./End-To-End-Encryption.md) itself, the introduction of temporary encryption keys impacts all use-cases that implicitly rely on data encryption, such as:

- New activations (using all supported methods)
- Obtaining and changing activation name from the mobile app.
- Secure Vault
- MAC-based Tokens
- Obtaining User Info
- Confirmation of the Recovery Codes
- Protocol upgrade