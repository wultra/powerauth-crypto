# Basic Definitions

The goal of this chapter is to define used functions related to cryptography and data manipulation. The definitions crafted in this chapter are then used in pseudo-codes in documentation. You can learn more about actual implementation of following functions in the "Implementation Notes" section.

## Cryptographic Functions

The following basic cryptography algorithms and parameters are used in the PowerAuth cryptography description:

### `AES`

A symmetric key encryption algorithm, uses CBC mode of operation. It defines the following methods:

#### `AES.Encrypt(byte[] original, byte[] iv, SecretKey key)`

Encrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation:

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key);
```

#### `AES.Encrypt(byte[] original, byte[] iv, SecretKey key, String transformation)`

Encrypt bytes using symmetric key with given initialization vector and given cipher transformation.

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key, String transformation);
```

#### `AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key)`

Decrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation:

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key);
```

#### `AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key, String transformation)`

Decrypt bytes using symmetric key with given initialization vector and given cipher transformation.

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key, String transformation);
```

### `PBKDF2`

An algorithm for key stretching, converts a short password into long key by performing repeated hash iteration on the original data. HMAC-SHA1 algorithm is used for a pseudo-random function. Implementations must make sure resulting key is converted into a format usable by the AES algorithm.

The following method is defined for this algorithm:

#### `PBKDF2.expand(char[] passwd, byte[] salt, long iter, long lenInBits)`

Stretch the password using given number of iterations to achieve key of given length in bits. Use a provided salt value.

```java
SecretKey expandedKey = PBKDF2.expand(char[] password, byte[] salt, long iterations, long lengthInBits);
```


### `X9.63` (with SHA256)

A standard KDF function based on X9.63, with SHA256 as an internal hash function. It uses iterations of SHA256 hash function to derive a key of expected `length` of bytes.

#### `KDF_X9_63_SHA256.derive(byte[] secret, byte[] info, int length)`

Derive a key of expected length from original secret value, using additional info byte value.

```java
byte[] bytes = KDF_X9_63_SHA256.derive(byte[] secret, byte[] info, int length);
```

### `ECDSA`

An algorithm for elliptic curve based signatures, uses SHA256 hash algorithm and P256r1 EC curve. It defines the following operations:

#### `ECDSA.sign(byte[] data, PrivateKey privateKey)`

Compute signature of given data with a private key.

```java
byte[] signature = ECDSA.sign(byte[] data, PrivateKey privateKey);
```

#### `ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey)`

Verify the signature for given data using a given public key.

```java
boolean isValid = ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey);
```

### `ECDH`

An algorithm for elliptic curve Diffie-Hellman, uses P256r1 curve. We define a single operation on ECDH, a symmetric key deduction between parties A and B:

#### `ECDH.phase(PrivateKey privateKeyA, PublicKey publicKeyB)`

Derive a shared secret using a private key of party A and a public key of party B.

```java
SecretKey secretKey = ECDH.phase(PrivateKey privateKeyA, PublicKey publicKeyB);
```

### `KDF`

A key derivation function used to derive a symmetric key with specific "index" from a given master key. Uses `AES` algorithm with the zero initialization vector to derive the new key in following way: `index` is converted to bytes, XORed with a 16 byte long zero array (to get 16 byte long array with bytes from the index) and AES encrypted using provided symmetric key `masterKey`.

#### `KDF.derive(SecretKey masterKey, long index)`

Obtained a key derived from a master key using a provided index.

```java
SecretKey derivedKey = KDF.derive(SecretKey masterKey, long index);
```

### `KDF_INTERNAL`

A second key derivation function for the algorithm internal purposes used to derive a symmetric key with specific "index" (in this case, `byte[16]`) from a given master key. Uses `HMAC-SHA256` to derive the new key in following way:

The `index` used as `HMAC-SHA256` key, provided symmetric key `masterKey` is converted to key bytes used as `HMAC-SHA256` data, resulting 32B long byte array is then XORed on per-byte basis (0th with 16th, 1st with 17th, etc.) to obtain 16B long byte array.

#### `KDF_INTERNAL.derive(SecretKey masterKey, byte[] index)`

Obtained a key derived from a master key using a provided index.

```java
SecretKey derivedKey = KDF_INTERNAL.derive(SecretKey masterKey, byte[] index);
```

## Helper Functions

These functions are used in the pseudo-codes:

### Key Generators.

#### `KeyGenerator.randomKeyPair()`

Generate a new EC key pair for the P256r1 elliptic curve.

```java
KeyPair keyPair = KeyGenerator.randomKeyPair();
```

### Key Conversion Utilities.

#### `KeyConversion.getBytes(PrivateKey privKey)`

Get bytes from the EC private key by encoding the D value (the number defining the EC private key).

```java
byte[] privateKeyBytes = KeyConversion.getBytes(PrivateKey privKey)
```

#### `KeyConversion.privateKeyFromBytes(byte[] privKeyBytes)`

Get EC key pair private key by decoding the bytes into the original D value (the number defining the EC private key).

```java
PrivateKey privateKey = KeyConversion.privateKeyFromBytes(byte[] privKeyBytes);
```

#### `KeyConversion.getBytes(PublicKey pubKey)`

Get bytes from the EC public key by encoding the Q value (the point defining the EC public key).

```java
byte[] publicKeyBytes = KeyConversion.getBytes(PublicKey pubKey);
```

#### `KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes)`

Get EC public key by decoding the bytes into the original Q value (the point defining the EC public key).

```java
PublicKey publicKey = KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes);
```

#### `KeyConversion.getBytes(SecretKey secretKey)`

Get bytes from the symmetric key (using the `getEncoded` method).

```java
byte[] secretKeyBytes = KeyConversion.getBytes(SecretKey secretKey);
```

#### `KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes)`

Create a symmetric key using provided bytes.

```java
SecretKey secretKey = KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes);
```

### Random Data Generators.

#### `Generator.randomBytes(int N)`

Generate N random bytes using a secure random generator.

```java
byte[] randomBytes = Generator.randomBytes(int N);
```

#### `Generator.randomBase32String(int N)`

Generate string in Base32 encoding with N characters using a secure random generator.

```java
String randomBase32 = Generator.randomBase32String(int N);
```

#### `Generator.randomUUID()`

Generate a new UUID level 4 and return it in string representation.

```java
String uuid = Generator.randomUUID();
```

#### `Generator.randomActivationCode()`

Generate a new `ACTIVATION_CODE`. See [Activation Code](./Activation-Code.md) for more details.

```java
String code = Generator.randomActivationCode();
```

#### `Generator.buildActivationCode(byte[10] randomBytes)`

Function return an activation code from given random data.

```java
String code = Generator.buildActivationCode(byte[10] randomBytes)
```

### MAC Functions

#### `Mac.hmacSha256(SecretKey key, byte[] message)`

Compute HMAC-SHA256 signature for given message using provided symmetric key.

```java
byte[] signature = Mac.hmacSha256(SecretKey key, byte[] message);
```

### Hashing Functions.

#### `Hash.sha256(byte[] original)`

Compute SHA256 hash of a given input.

```java
byte[] hash = Hash.sha256(byte[] original);
```

### Password Hashing

#### `PasswordHash.hash(byte[] password)`

Compute Argon2 hash for given password. Hash is stored in Modular Crypt Format.

```java
String hash = PasswordHash.hash(byte[] password);
```

#### `PasswordHash.verify(byte[] password, String hash)`

Verify password against Argon2 hash stored in Modular Crypt Format.

```java
boolean matches = PasswordHash.verify(byte[] password, String hash);
```

### Utility Functions.

#### `ByteUtils.zeroBytes(int N)`

Generate buffer with N zero bytes.

```java
byte[] zeroBytes = ByteUtils.zeroBytes(int N);
```

#### `ByteUtils.truncate(byte[] bytes, int N)`

Get last N bytes of given byte array.

```java
byte[] truncatedBytes = ByteUtils.truncate(byte[] bytes, int N);
```

#### `ByteUtils.getInt(byte[4] bytes)`

Get integer from 4 byte long byte array.

```java
int integer = ByteUtils.getInt(byte[4] bytes);
```

#### `ByteUtils.getLong(byte[8] bytes)`

Get long value from 8 byte long byte array.

```java
long value = ByteUtils.getLong(byte[8] bytes);
```

#### `ByteUtils.concat(byte[] a, byte[] b)`

Concatenate two byte arrays - append `b` after `a`.

```java
byte[] result = ByteUtils.concat(byte[] a, byte[] b);
```

#### `ByteUtils.convert32Bto16B(byte[] bytes32)`

Converts 32b long byte array to 16b long array by xor-ing the first 16b with the second 16b, byte-by-byte.

```java
byte[] result = ByteUtils.convert32Bto16B(byte[] bytes32);
```

#### `ByteUtils.subarray(byte[] bytes, int startIndex, int length)`

Obtain subarray of a byte array, starting with index `startIndex` with a given length.

```java
byte[] result = ByteUtils.subarray(byte[] bytes, int startIndex, int length);
```

#### `ByteUtils.copy(byte[] src, int srcPos, byte[] dst, int dstPos, int len)`

Copies `length` of bytes from the specified source array of bytes, beginning at the specified position, to the specified position of the destination array.

```java
ByteUtils.copy(byte[] source, int sourcePosition, byte[] destination, int destinationPosition, int length);
```
