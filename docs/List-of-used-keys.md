# List of Used Keys

Following keys are used in the PowerAuth cryptography scheme.

| name | created as | purpose |
|---|---|---|
| `KEY_DEVICE_PRIVATE` | ECDH - private key | Generated on client to allow construction of `KEY_MASTER_SECRET` |
| `KEY_DEVICE_PUBLIC`  | ECDH - public key  | Generated on client to allow construction of `KEY_MASTER_SECRET` |
| `KEY_SERVER_PRIVATE` | ECDH - private key | Generated on server to allow construction of `KEY_MASTER_SECRET` |
| `KEY_SERVER_PUBLIC`  | ECDH - public key  | Generated on server to allow construction of `KEY_MASTER_SECRET` |
| `KEY_SERVER_MASTER_PRIVATE` | ECDH - private key | Stored on server, used to assure authenticity of `KEY_DEVICE_PUBLIC` while transferring from server to client |
| `KEY_SERVER_MASTER_PUBLIC`  | ECDH - public key  | Stored on client, used to assure authenticity of `KEY_DEVICE_PUBLIC` while transferring from server to client |
| `KEY_MASTER_SECRET`         | ECDH - pre-shared  | A key deduced using ECDH derivation, `KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE, KEY_SERVER_PUBLIC) = ECDH.phase(KEY_SERVER_PRIVATE, KEY_DEVICE_PUBLIC)` |
| `KEY_SIGNATURE_POSSESSION`  | KDF derived key from `KEY_MASTER_SECRET` | A signing key associated with the possession, factor deduced using KDF derivation with `INDEX = 1`, `KEY_SIGNATURE_POSSESSION = KDF.expand(KEY_MASTER_SECRET, 1)`, used for subsequent request signing |
| `KEY_SIGNATURE_KNOWLEDGE`   | KDF derived key from `KEY_MASTER_SECRET` | A key associated with the knowledge factor, deduced using KDF derivation with `INDEX = 2`, `KEY_SIGNATURE_KNOWLEDGE = KDF.expand(KEY_MASTER_SECRET, 2)`, used for subsequent request signing |
| `KEY_SIGNATURE_BIOMETRY`    | KDF derived key from `KEY_MASTER_SECRET` | A key associated with the biometry factor, deduced using KDF derivation with `INDEX = 3`, `KEY_SIGNATURE_BIOMETRY = KDF.derive(KEY_MASTER_SECRET, 3)`, used for subsequent request signing |
| `KEY_TRANSPORT`             | KDF derived key from `KEY_MASTER_SECRET` | A key deduced using KDF derivation with `INDEX = 1000`, `KEY_TRANSPORT = KDF.expand(KEY_MASTER_SECRET, 1000)`, used for encrypted data transport. This key is used as master transport key for end-to-end encryption key derivation. |
| `KEY_ENCRYPTION_VAULT`      | KDF derived key from `KEY_MASTER_SECRET` | A key deduced using KDF derivation with `INDEX = 2000`, `KEY_ENCRYPTION_VAULT = KDF.expand(KEY_MASTER_SECRET, 2000)`, used for encrypting a vault that stores the secret data, such as `KEY_DEVICE_PRIVATE`. |
| `KEY_TRANSPORT_IV`          | KDF derived key from `KEY_TRANSPORT`     | A key deduced using KDF derivation with `INDEX = 3000`, `KEY_ENCRYPTION_IV = KDF.expand(KEY_TRANSPORT, 3000)`, used for derivation of initial vector, that encrypts activation status blob. |
| `KEY_TRANSPORT_CTR`         | KDF derived key from `KEY_TRANSPORT`     | A key deduced using KDF derivation with `INDEX = 4000`, `KEY_TRANSPORT_CTR = KDF.expand(KEY_TRANSPORT, 4000)`, used for computing hash from current value of hash-based counter. |
