# Key Derivation

As an outcome of the previous activation steps, a single shared secret `KEY_MASTER_SECRET` is established for PowerAuth Client and PowerAuth Server. While additional shared secrets could be established by repeating the activation process, this may not be very handy in all situations, since the activation process is quite complex and not very user-friendly.

For this reason, PowerAuth establishes the concept of derived keys. Each derived key is computed using the KDF algorithm (see "Implementation details" section for the definition):

```java
SecretKey KEY_DERIVED = KDF.derive(KEY_MASTER_SECRET, INDEX);
```

PowerAuth Client is supposed to store only these derived keys and a server public key. Saying the same information more explicitly, PowerAuth Client must not store `KEY_MASTER_SECRET` or `KEY_DEVICE_PRIVATE` unencrypted. The `KEY_DEVICE_PRIVATE` is stored in encrypted vault - see the "Encrypted vault" section of this chapter. As a result, storing `KEY_MASTER_SECRET` is not necessary.

## Reserved Derived Keys

Following specific derived keys are reserved for the PowerAuth:

### Request Signing Keys

#### Related to "Possession Factor"

First key used for signature computing, related to the "possession factor" in M-FA, deduced as:

```java
SecretKey KEY_SIGNATURE_POSSESSION = KDF.derive(KEY_MASTER_SECRET, 1);
```

This key should be stored encrypted using a key derived using PowerAuth Client device fingerprint, for example unique device ID, Wi-Fi MAC address, etc. The way of deriving encryption key is not defined in PowerAuth specification.

#### Related to "Knowledge Factor"

Second key used for signature computing, related to the "knowledge factor" in M-FA, deduced as:

```java
SecretKey KEY_SIGNATURE_KNOWLEDGE = KDF.derive(KEY_MASTER_SECRET, 2);
```

This key should be stored encrypted using a key derived from a password or a PIN code. PowerAuth Client should derive the encryption key using PBKDF2 algorithm with at least 10 000 iterations:

```java
char[] password = "1234".toCharArray();
byte[] salt = Generator.randomBytes(16);
int iterations = 10000;
int lengthInBits = 128;
SharedKey encryptionKey = PBKDF2.expand(password, salt, iterations, lengthInBits);
byte[] iv = Generator.zeroBytes(16);
byte[] keyKnowledgeBytes = KeyConversion.getBytes(KEY_SIGNATURE_KNOWLEDGE);
byte[] C_KEY_SIGNATURE_KNOWLEDGE = AES.encrypt(keyKnowledgeBytes, iv, encryptionKey, "AES/CBC/NoPadding");

// Store `C_KEY_SIGNATURE_KNOWLEDGE` and `salt`.
```

The key `KEY_SIGNATURE_KNOWLEDGE` is then decrypted using the inverse algorithm - stored salt end entered password is used to decrypt the encrypted `C_KEY_SIGNATURE_KNOWLEDGE`.

#### Related to "Biometry Factor"

First key used for signature computing, related to the "inherence factor" in M-FA, deduced as:

```java
SecretKey KEY_SIGNATURE_BIOMETRY = KDF.derive(KEY_MASTER_SECRET, 3);
```

This key should be stored encrypted using a biometric storage, if it is available. Usually, the biometric storage is provided as a transparent mechanism and therefore, it should be used as provided.

### Master Transport Key

Key used for transferring an activation record status blob, deduced as:

```java
SecretKey KEY_TRANSPORT = KDF.derive(KEY_MASTER_SECRET, 1000);
```

This key should be stored encrypted using a key derived using PowerAuth Client device fingerprint, for example unique device ID, Wi-Fi MAC address, etc. - generally the same way as `KEY_SIGNATURE_POSSESSION`. The way of deriving encryption key is not defined in PowerAuth specification.

### Encrypted Vault

#### Vault Encryption Key

An encryption key used for storing the original private key `KEY_DEVICE_PRIVATE`, deduced as:

```java
SecretKey KEY_ENCRYPTION_VAULT = KDF.derive(KEY_MASTER_SECRET, 2000);
```

This key **MUST NOT** be stored on the PowerAuth Client at all. It must be sent upon successful 2FA authentication from PowerAuth Server. The `KEY_ENCRYPTION_VAULT` is sent from the server encrypted using they `KEY_TRANSPORT` key (see above):

```java
byte[] C_KEY_ENCRYPTION_VAULT = AES.encrypt(KEY_ENCRYPTION_VAULT, ByteUtils.zeroBytes(16), KEY_TRANSPORT);
```

The primary use-case for having an encrypted vault is storage of the original device primary key `KEY_DEVICE_PRIVATE`. This key should be stored on the device in a following way just after the activation:

```java
byte[] C_KEY_DEVICE_PRIVATE = AES.encrypt(KEY_DEVICE_PRIVATE, ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT);
```

Since `KEY_ENCRYPTION_VAULT` is not stored on the client side, it must be fetched using authenticated request on server for decryption. Once server verifies the authentication status (signature matches) and returns encrypted `C_KEY_ENCRYPTION_VAULT` key, client can decrypt it using `KEY_ENCRYPTION_VAULT_TRANSPORT` and then decrypt `KEY_DEVICE_PRIVATE`. The whole request and response protection is based on our ECIES scheme. 
