# PowerAuth Key Derivation

As an outcome of the previous activation steps, a single shared secret `KEY_MASTER_SECRET` is established for PowerAuth 2.0 Client and PowerAuth 2.0 Server. While additional shared secrets could be established by repeating the activation process, this may not be very handy in all situations, since the activation process is quite complex and not very user-friendly.

For this reason, PowerAuth 2.0 establishes the concept of derived keys. Each derived key is computed using the KDF algorithm (see "Implementation details" section for the definition):

- `KEY_DERIVED = KDF(KEY_MASTER_SECRET, INDEX)`

## Reserved derived keys

Following specific derived keys are reserved for the PowerAuth 2.0:

### Request signing keys

#### Related to "possession factor"

First key used for signature computing, related to the "possession factor" in M-FA, deduced as:

`KEY_SIGNATURE_POSSESSION = KDF(KEY_MASTER_SECRET, 1)`

#### Related to "knowledge factor"

Second key used for signature computing, related to the "knowledge factor" in M-FA, deduced as:

`KEY_SIGNATURE_KNOWLEDGE = KDF(KEY_MASTER_SECRET, 2)`

#### Related to "biometry factor"

First key used for signature computing, related to the "inherence factor" in M-FA, deduced as:

`KEY_SIGNATURE_BIOMETRY = KDF(KEY_MASTER_SECRET, 3)`

### Master transport key

Key used for transferring an activation record status blob, deduced as:

`KEY_TRANSPORT = KDF(KEY_MASTER_SECRET, 1000)`

### Encrypted vault

#### Vault encryption key transport key

Transport key used for transferring an encryption key for vault encryption `KEY_ENCRYPTION_VAULT`. It is deduced using the master transport key and counter (same one as the one used for authentication of the request that unlocks the key).

`KEY_ENCRYPTION_VAULT_TRANSPORT = KDF(KEY_TRANSPORT, CTR)`

#### Vault encryption key

An encryption key used for storing the original private key `KEY_DEVICE_PRIVATE`, deduced as:

`KEY_ENCRYPTION_VAULT = KDF(KEY_MASTER_SECRET, 2000)`

This key must not be stored on the PowerAuth 2.0 Client at all. It must be sent upon successful authentication from PowerAuth 2.0 Server. The `KEY_ENCRYPTION_VAULT` is sent from the server encrypted using one-time transport key `KEY_ENCRYPTION_VAULT_TRANSPORT` key (see above):

`C_KEY_ENCRYPTION_VAULT = AES.encrypt(KEY_ENCRYPTION_VAULT, ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT_TRANSPORT)`
