# Basic Definitions

The goal of this chapter is to define used functions related to cryptography and data manipulation. The definitions crafted in this chapter are then used in pseudo-codes in documentation. You can learn more about actual implementation of following functions in the "Implementation Notes" section.

## Cryptographic Functions

The following basic cryptography algorithms and parameters are used in the PowerAuth cryptography description:

### AES Symmetric Encryption

A symmetric key encryption algorithm, uses CBC mode of operation. It defines the following methods:

#### Encryption

Encrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation:

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key);
```

Encrypt bytes using symmetric key with given initialization vector and given cipher transformation.

```java
byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key, String transformation);
```

#### Decryption

Decrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation:

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key);
```

Decrypt bytes using symmetric key with given initialization vector and given cipher transformation.

```java
byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key, String transformation);
```

### PBKDF2

An algorithm for key stretching, converts a short password into long key by performing repeated hash iteration on the original data. HMAC-SHA1 algorithm is used for a pseudo-random function. Implementations must make sure resulting key is converted into a format usable by the AES algorithm.

The following method will stretch the password using given number of iterations to achieve key of given length in bits. Use a provided salt value.

```java
SecretKey expandedKey = PBKDF2.expand(char[] password, byte[] salt, long iterations, long lengthInBits);
```


### X9.63 KDF with SHA256

A standard KDF function based on X9.63, with SHA256 as an internal hash function. It uses iterations of SHA256 hash function to derive a key of expected `length` of bytes.

Use the following method to derive a key of expected length from original secret value, using additional info byte value.

```java
byte[] bytes = KDF_X9_63_SHA256.derive(byte[] secret, byte[] info, int length);
```

### ECDSA Signatures

An algorithm for elliptic curve based signatures, uses SHA256 hash algorithm and P256r1 EC curve. It defines the following operations:

#### Data Signing

Compute signature of given data with a private key.

```java
byte[] signature = ECDSA.sign(byte[] data, PrivateKey privateKey);
```

#### Signature Verification

Verify the signature for given data using a given public key.

```java
boolean isValid = ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey);
```

### ECDH Key Agreement

An algorithm for elliptic curve Diffie-Hellman, uses P256r1 curve. We define a single operation on ECDH, a symmetric key deduction between parties A and B:

Derive a shared secret using a private key of party A and a public key of party B using the follwing method.

```java
SecretKey secretKey = ECDH.phase(PrivateKey privateKeyA, PublicKey publicKeyB);
```

### KDF

A key derivation function used to derive a symmetric key with specific "index" from a given master key. Uses `AES` algorithm with the zero initialization vector to derive the new key in following way: `index` is converted to bytes, XORed with a 16 byte long zero array (to get 16 byte long array with bytes from the index) and AES encrypted using provided symmetric key `masterKey`.

To obtain a key derived from a master key using a provided index, use:

```java
SecretKey derivedKey = KDF.derive(SecretKey masterKey, long index);
```

### KDF_INTERNAL

A second key derivation function for the algorithm internal purposes used to derive a symmetric key with specific "index" (in this case, `byte[16]`) from a given master key. Uses `HMAC-SHA256` to derive the new key in following way:

The `index` used as `HMAC-SHA256` key, provided symmetric key `masterKey` is converted to key bytes used as `HMAC-SHA256` data, resulting 32B long byte array is then XORed on per-byte basis (0th with 16th, 1st with 17th, etc.) to obtain 16B long byte array.

To obtain a key derived from a master key using a provided index, use:

```java
SecretKey derivedKey = KDF_INTERNAL.derive(SecretKey masterKey, byte[] index);
```

## Helper Functions

These functions are used in the pseudo-codes:

### Key Generators.

#### Generate Random Key Pair

Generate a new EC key pair for the P256r1 elliptic curve.

```java
KeyPair keyPair = KeyGenerator.randomKeyPair();
```

### Key Conversion Utilities.

#### Convert Private Key to Bytes

Get bytes from the EC private key by encoding the D value (the number defining the EC private key).

```java
byte[] privateKeyBytes = KeyConversion.getBytes(PrivateKey privKey)
```

#### Convert Bytes to Private Key

Get EC key pair private key by decoding the bytes into the original D value (the number defining the EC private key).

```java
PrivateKey privateKey = KeyConversion.privateKeyFromBytes(byte[] privKeyBytes);
```

#### Convert Public Key to Bytes

Get bytes from the EC public key by encoding the Q value (the point defining the EC public key).

```java
byte[] publicKeyBytes = KeyConversion.getBytes(PublicKey pubKey);
```

#### Convert Bytes to Public Key

Get EC public key by decoding the bytes into the original Q value (the point defining the EC public key).

```java
PublicKey publicKey = KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes);
```

#### Convert Secret Key to Bytes

Get bytes from the symmetric key (using the `getEncoded` method).

```java
byte[] secretKeyBytes = KeyConversion.getBytes(SecretKey secretKey);
```

#### Convert Bytes to Secret Key

Create a symmetric key using provided bytes.

```java
SecretKey secretKey = KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes);
```

### Random Data Generators.

#### Generate Random Data

Generate N random bytes using a secure random generator.

```java
byte[] randomBytes = Generator.randomBytes(int N);
```

#### Generate Random Base32 String

Generate string in Base32 encoding with N characters using a secure random generator.

```java
String randomBase32 = Generator.randomBase32String(int N);
```

#### Generate Random UUID

Generate a new UUID level 4 and return it in string representation.

```java
String uuid = Generator.randomUUID();
```

#### Generate Random Activation Code

Generate a new `ACTIVATION_CODE`. See [Activation Code](./Activation-Code.md) for more details.

```java
String code = Generator.randomActivationCode();
```

#### Build Activation Code With Random Bytes

Function return an activation code from given random data.

```java
String code = Generator.buildActivationCode(byte[10] randomBytes)
```

### MAC Functions

#### HMAC-SHA256

Compute HMAC-SHA256 signature for given message using provided symmetric key.

```java
byte[] signature = Mac.hmacSha256(SecretKey key, byte[] message);
```

### Hashing Functions.

#### SHA256

Compute SHA256 hash of a given input.

```java
byte[] hash = Hash.sha256(byte[] original);
```

### Password Hashing

#### Compute Password Hash

Compute Argon2 hash for given password. Hash is stored in Modular Crypt Format.

```java
String hash = PasswordHash.hash(byte[] password);
```

#### Verify Password Hash

Verify password against Argon2 hash stored in Modular Crypt Format.

```java
boolean matches = PasswordHash.verify(byte[] password, String hash);
```

### Utility Functions.

#### Obtain Zero Byte Array

Generate buffer with N zero bytes.

```java
byte[] zeroBytes = ByteUtils.zeroBytes(int N);
```

#### Truncate Array

Get last N bytes of given byte array.

```java
byte[] truncatedBytes = ByteUtils.truncate(byte[] bytes, int N);
```

#### Get Numbers From Byte Array

Get integer value from big endian encoded byte array.

```java
int integer = ByteUtils.getInt(byte[4] bytes);
```

Get long value from big endian encoded byte array.

```java
long value = ByteUtils.getLong(byte[8] bytes);
```

#### Encode Primitive Types To Byte Array

Encode short value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(short n);
```

Encode int value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(int n);
```

Encode long value into byte array in big endian order.

```java
byte[] encoded = ByteUtils.encode(long n);
```

Encode string into sequence of bytes with UTF-8 encoding.

```java
byte[] encoded = ByteUtils.encode(String s);
```

#### Concatenate Data

Concatenate two or more byte arrays.

```java
byte[] ByteUtils.concat(byte[]... args) {
    byte[] result = new byte[0];
    for (byte[] component : args) {
        if (component != null && component.length > 0) {
          byte[] tmp = new byte[result.length + component.length];
          ByteUtils.copy(result, 0, tmp, 0, result.length);
          ByteUtils.copy(component, 0, tmp, result.length, component.length);
          result = tmp;
        }
    }
    return result;
}
```

Concatenate multiple byte array elements and prepend the length of each element.

```java
byte[] ByteUtils.concatWithSizes(byte[]... args) {
    byte[] result = new byte[0];
    for (byte[] component : args) {
        if (component != null) {
            result = ByteUtils.concat(result, ByteUtils.encode(component.length), component);
        } else {
            result = ByteUtils.concat(result, ByteUtils.encode((int)0));
        }
    }
    return result;
}
```

Concatenate multiple string elements and prepend the length of each element.

```java
byte[] ByteUtils.concatWithSizes(String... args) {
    byte[] result = new byte[0];
    for (String component : args) {
        if (component != null) {
            byte[] componentBytes = ByteUtils.encode(component);
            result = ByteUtils.concat(result, ByteUtils.encode(componentBytes.length), componentBytes);
        } else {
            result = ByteUtils.concat(result, ByteUtils.encode((int)0));
        }
    }
    return result;
}
```

#### Convert 32b Array to 16b

Converts 32b long byte array to 16b long array by xor-ing the first 16b with the second 16b, byte-by-byte.

```java
byte[] result = ByteUtils.convert32Bto16B(byte[] bytes32);
```

#### Obtain Sub-Array

Obtain subarray of a byte array, starting with index `startIndex` with a given length.

```java
byte[] result = ByteUtils.subarray(byte[] bytes, int startIndex, int length);
```

#### Copy Arrays

Copies `length` of bytes from the specified source array of bytes, beginning at the specified position, to the specified position of the destination array.

```java
ByteUtils.copy(byte[] source, int sourcePosition, byte[] destination, int destinationPosition, int length);
```

#### Current Time

Get UNIX timestamp in milliseconds, since 1.1.1970.

```java
long timestamp = Time.getTimestamp();
```
