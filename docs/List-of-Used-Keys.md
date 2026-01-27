# List of used keys

The following keys are used in the PowerAuth cryptography scheme.

| name                                 | created as                                     | purpose                                                                                                                                                      |
|--------------------------------------|------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| _key_master *_                       |                                                |                                                                                                                                                              |
| `KEY_MASTER_P256_PRIVATE`            | ECDSA/ECDH - private key                       | Stored on server, used for backward compatibility with older clients                                                                                         |
| `KEY_MASTER_P256_PUBLIC`             | ECDSA/ECDH - public key                        | Used by older clients                                                                                                                                        |
| `KEY_MASTER_ECDSA_P384_PRIVATE`      | ECDSA - private key                            | Stored on server, used to assure authenticity of `KEY_SERVER_*_PUBLIC` while transferring from server to client                                              |
| `KEY_MASTER_ECDSA_P384_PUBLIC`       | ECDSA - public key                             | Stored on client, used to verify authenticity of data while transferring from server to client.                                                              |
| `KEY_MASTER_MLDSA65_PRIVATE`         | ML-DSA - private key                           | Stored on server, used to assure authenticity of `KEY_SERVER_*_PUBLIC` while transferring from server to client                                              |
| `KEY_MASTER_MLDSA65_PUBLIC`          | ML-DSA - public key                            | Stored on client, used to verify authenticity of data while transferring from server to client.                                                              |
| `KEY_MASTER_MLDSA87_PRIVATE`         | ML-DSA - private key                           | Stored on server, used to assure authenticity of `KEY_SERVER_*_PUBLIC` while transferring from server to client                                              |
| `KEY_MASTER_MLDSA87_PUBLIC`          | ML-DSA - public key                            | Stored on client, used to verify authenticity of data while transferring from server to client.                                                              |
| _key_device_*_                       |                                                |                                                                                                                                                              |
| `KEY_DEVICE_P256_PRIVATE`            | ECDH/ECDSA - private key                       | Used by older clients                                                                                                                                        |
| `KEY_DEVICE_P256_PUBLIC`             | ECDH/ECDSA - public key                        | Used by older clients                                                                                                                                        |
| `KEY_DEVICE_ECDSA_P384_PRIVATE`      | ECDSA - private key                            | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_DEVICE_ECDSA_P384_PUBLIC`       | ECDSA - public key                             | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| `KEY_DEVICE_MLDSA65_PRIVATE`         | ML-DSA - private key                           | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_DEVICE_MLDSA65_PUBLIC`          | ML-DSA - public key                            | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| `KEY_DEVICE_MLDSA87_PRIVATE`         | ML-DSA - private key                           | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_DEVICE_MLDSA87_PUBLIC`          | ML-DSA - public key                            | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| _key_server *_                       |                                                |                                                                                                                                                              |
| `KEY_SERVER_P256_PRIVATE`            | ECDH/ECDSA - private key                       | Used by older clients                                                                                                                                        |
| `KEY_SERVER_P256_PUBLIC`             | ECDH/ECDSA - public key                        | Used by older clients                                                                                                                                        |
| `KEY_SERVER_ECDSA_P384_PRIVATE`      | ECDSA - private key                            | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_SERVER_ECDSA_P384_PUBLIC`       | ECDSA - public key                             | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| `KEY_SERVER_MLDSA65_PRIVATE`         | ML-DSA - private key                           | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_SERVER_MLDSA65_PUBLIC`          | ML-DSA - public key                            | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| `KEY_SERVER_MLDSA87_PRIVATE`         | ML-DSA - private key                           | Stored on client, used to assure authenticity of data signed by the user                                                                                     |
| `KEY_SERVER_MLDSA87_PUBLIC`          | ML-DSA - public key                            | Stored on server, used to verify authenticity of data signed by the user                                                                                     |
| _other_                              |                                                |                                                                                                                                                              |
| `KEY_TEMPORARY_SECRET`               | ECDH/Hybrid shared secret                      | A key deduced using `SharedSecret` protocol at the requested level of security. This is a temporary shared secret for E2EE purposes                          |
| `KEY_ACTIVATION_SECRET`              | ECDH/Hybrid shared secret                      | A key deduced using `SharedSecret` protocol at the requested level of security. This is a long term shared secret created between the client and the server. |
| `KEY_AUTHENTICATION_CODE_POSSESSION` | KDF derived key from `KDK_AUTHENTICATION_CODE` | A signing key associated with the possession factor.`                                                                                                        |
| `KEY_AUTHENTICATION_CODE_KNOWLEDGE`  | KDF derived key from `KDK_AUTHENTICATION_CODE` | A key associated with the knowledge factor.                                                                                                                  |
| `KEY_AUTHENTICATION_CODE_BIOMETRY`   | KDF derived key from `KDK_AUTHENTICATION_CODE` | A key associated with the biometry factor.                                                                                                                   |
| `KEK_AUTHENTICATION_CODE_POSSESSION` | Key derived from unique device's data          | Encrypts and decrypts `KEY_AUTHENTICATION_CODE_POSSESSION` on the client.                                                                                    |
| `KEK_AUTHENTICATION_CODE_KNOWLEDGE`  | Derived from user's password or PIN            | Encrypts and decrypts `KEY_AUTHENTICATION_CODE_KNOWLEDGE` on the client.                                                                                     |
| `KEK_AUTHENTICATION_CODE_BIOMETRY`   | Platform specific                              | Encrypts and decrypts `KEY_AUTHENTICATION_CODE_BIOMETRY` on the client.                                                                                      |

> TODO: the table above is not updated yet.

## Index registry

The following table contains the list of all derivation indexes for KDF function used in the protocol.

| Label                           | Derived key                        | Source key                               | Description                                                                                                                |
|---------------------------------|------------------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| _Authentication Codes_          |                                    |                                          |                                                                                                                            |
| `auth`                          | **KDK_AUTHENTICATION_CODE**        | KEY_ACTIVATION_SECRET                    | Base for PowerAuth authentication code purpose                                                                             |
| `auth/possession`               | KEY_AUTHENTICATION_CODE_POSSESSION | KDK_AUTHENTICATION_CODE                  | Possession factor                                                                                                          |
| `auth/knowledge`                | KEY_AUTHENTICATION_CODE_KNOWLEDGE  | KDK_AUTHENTICATION_CODE                  | Initial knowledge factor, before password is changed                                                                       |
| `auth/biometry`                 | KEY_AUTHENTICATION_CODE_BIOMETRY   | KDK_AUTHENTICATION_CODE                  | Initial biometry factor, if biometry is enabled in activation process                                                      |
| _Shared Secret_                 |                                    |                                          |                                                                                                                            |   
| `shared-secret/ec-p384`         | KEY_SHARED_SECRET<sup>3</sup>      | ECDHE                                    | Shared secret calculated with EC_P384 algorithm                                                                            |
| `shared-secret/ec-p384-ml-l3`   | KEY_SHARED_SECRET<sup>3</sup>      | ECDHE+ML-KEM                             | Shared secret calculated with EC_P384_ML_L3 algorithm                                                                      |
| _Encryption_                    |                                    |                                          |
| `enc`                           | **KDK_ENCRYPTION**                 | KEY_ACTIVATION_SECRET                    | Base for encryption purpose                                                                                                |
| `aead/enc`                      | KEY_ENC                            | BASE_KEY<sup>1</sup>                     | AEAD key for encryption                                                                                                    |
| `aead/mac`                      | KEY_MAC                            | BASE_KEY<sup>1</sup>                     | AEAD key for authentication                                                                                                |
| `enc/local`                     | KEY_LOCAL_DATA                     | DEVICE_KEY<sup>2</sup>                   | Key that encrypts local data that suppose to be always available                                                           |
| `enc/kek-possession`            | KEK_AUTHENTICATION_CODE_POSSESSION | DEVICE_KEY<sup>2</sup>                   | Key that encrypts KEY_AUTHENTICATION_CODE_POSSESSION                                                                       |
| _Vault_                         |                                    |                                          |                                                                                                                            |
| `vault`                         | **KDK_VAULT**                      | KEY_ACTIVATION_SECRET                    | Base for local vault encryption                                                                                            |
| `vault/kek-device-private`      | KEK_DEVICE_PRIVATE                 | KDK_VAULT                                | Key that encrypts KEY_DEVICE_PRIVATE                                                                                       |
| `vault/kdk-app-vault-knowledge` | KDK_APP_VAULT_KNOWLEDGE            | KDK_VAULT                                | KDK for application specific purposes, provided only after 2FA knowledge authentication                                    |
| `vault/kdk-app-vault-2fa`       | KDK_APP_VAULT_2FA                  | KDK_VAULT                                | KDK for application specific purposes, provided only after any 2FA authentication                                          |
| _Utility_                       |                                    |                                          |                                                                                                                            |
| `util`                          | **KDK_UTILITY**                    | KEY_ACTIVATION_SECRET                    | KDK for other purposes, always available                                                                                   |
| `util/mac/ctr-data`             | KEY_MAC_CTR_DATA                   | KDK_UTILITY                              | Compute MAC from hash based counter                                                                                        |
| `util/mac/status`               | KEY_MAC_STATUS                     | KDK_UTILITY                              | Compute MAC from activation status data                                                                                    |
| `util/mac/get-app-temp-key`     | KEY_MAC_GET_APP_TEMP_KEY           | APP_SECRET                               | Key for signing payload in getting temporary key request in application scope (APP_SECRET is decoded from Base64 constant) |                   
| `util/mac/get-act-temp-key`     | KEY_MAC_GET_ACT_TEMP_KEY           | KDK_UTILITY                              | Key for signing payload in getting temporary key request in activation scope                                               |
| `util/mac/personalized-data`    | KEY_MAC_PERSONALIZED_DATA          | KDK_UTILITY                              | Compute MAC for personalized data, typically displayed as QR code                                                          |
| `util/key-e2ee-sh2`             | KEY_E2EE_SHARED_INFO2              | KDK_UTILITY                              | Key for SHARED_INFO_2 calculation for E2EE                                                                                 |
| `util/app`                      | KDK_APP_UTILITY                    | KDK_UTILITY                              | KDK for application specific purposes                                                                                      |
| _Other_                         |                                    |                                          |                                                                                                                            |
| `other/expand-biometry-key`     | KEK_AUTHENTICATION_CODE_BIOMETRY   | 128-bit KEK_AUTHENTICATION_CODE_BIOMETRY | Expands 128 bit biometry factor related KEK to 256 bit                                                                     |

### Notes

> Note 1: In E2EE, `BASE_KEY` is equal to `KEY_TEMPORARY_SHARED_SECRET`.

> Note 2: `DEVICE_KEY` is calculated as `Hash.sha3_256("device-specific-data")`

> Note 3: `KEY_SHARED_SECRET` is KEY_ACTIVATION_SECRET or KEY_TEMPORARY_SECRET, depending on purpose of established secret.

### Example

The following example shows how to calculate the derived key. Let's say we want to get the value for `KEY_MAC_STATUS`:

```java
SecretKey KDK_UTILITY    = KDF.derive(KEY_ACTIVATION_SECRET, "util");
SecretKey KEY_MAC_STATUS = KDF.derive(KDK_UTILITY, "util/mac/status");
```
