# Basic Definitions

The goal of this chapter is to define used functions related to cryptography and data manipulation. The definitions crafted in this chapter are then used in pseudo-codes in documentation. You can learn more about actual implementation of following functions in the "Implementation Notes" section.

## Cryptographic Functions

Following basic cryptography algorithms and parameters are used in the PowerAuth cryptography description:

- **AES** - A symmetric key encryption algorithm, uses CBC mode of operation. It defines four methods:
  - `byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key)` - encrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation.
  - `byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key)` - decrypt bytes using symmetric key with given initialization vector and `AES/CBC/PKCS7Padding` transformation.
  - `byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key, String transformation)` - encrypt bytes using symmetric key with given initialization vector and given cipher transformation.
  - `byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key, String transformation)` - decrypt bytes using symmetric key with given initialization vector and given cipher transformation.

- **PBKDF2** - An algorithm for key stretching, converts a short password into long key by performing repeated hash iteration on the original data, HMAC-SHA1 algorithm is used for a pseudo-random function. Implementations must make sure resulting key is converted in format usable by AES algorithm. One method is defined for this algorithm:
  - `SecretKey expandedKey = PBKDF2.expand(char[] password, byte[] salt, long iterations, long lengthInBits)` - stretch the password using given number of iterations to achieve key of given length in bits, use given salt.

- **X9.63 (with SHA256)** - A standard KDF function based on X9.63, with SHA256 as an internal hash function. It uses iterations of SHA256 hash function to derive a key of expected `length` of bytes.
  - `byte[] bytes = KDF_X9_63_SHA256.derive(byte[] secret, byte[] info, int length)`

- **ECDSA** - An algorithm for elliptic curve based signatures, uses SHA256 hash algorithm and P256r1 EC curve. It defines two operations:
  - `byte[] signature = ECDSA.sign(byte[] data, PrivateKey privateKey)` - compute signature of given data and private key.
  - `boolean isValid = ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey)` - verify the signature for given data using a given public key.

- **ECDH** - An algorithm for elliptic curve with Diffie-Hellman key exchange, uses P256r1 curve. We define single operation on ECDH, a symmetric key deduction between parties A and B:
  - `SecretKey secretKey = ECDH.phase(PrivateKey privateKeyA, PublicKey publicKeyB)`

- **KDF** - A key derivation function used to derive a symmetric key with specific "index" from a given master key. Uses AES algorithm with zero initialization vector to derive the new key in following way: `index` is converted to bytes, XORed with a 16 byte long zero array (to get 16 byte long array with bytes from the index) and AES encrypted using provided symmetric key `masterKey`.
  - `SecretKey derivedKey = KDF.derive(SecretKey masterKey, long index)`

- **KDF_INTERNAL** - A second key derivation function for the algorithm internal purposes used to derive a symmetric key with specific "index" (in this case, byte[16]) from a given master key. Uses HMAC-SHA256 to derive the new key in following way: `index` used as HMAC-SHA256 key, provided symmetric key `masterKey` is converted to key bytes used as HMAC-SHA256 data, resulting 32B long byte array is then XORed on per-byte basis to obtain 16B ling byte array (0th with 16th, 1st with 17th, etc.).
  - `SecretKey derivedKey = KDF_INTERNAL.derive(SecretKey masterKey, byte[] index)`

## Helper Functions

These functions are used in the pseudo-codes:

- Key generators.
  - `KeyPair keyPair = KeyGenerator.randomKeyPair()` - Generate a new ECDH key pair using P256r1 elliptic curve.

- Key conversion utilities.
  - `byte[] privateKeyBytes = KeyConversion.getBytes(PrivateKey privKey)` - Get bytes from the ECDH key pair private key by encoding the D value (the number defining the ECDH private key).
  - `byte[] publicKeyBytes = KeyConversion.getBytes(PublicKey pubKey)` - Get bytes from the ECDH key pair public key by encoding the Q value (the point defining the ECDH public key).
  - `byte[] secretKeyBytes = KeyConversion.getBytes(SecretKey secretKey)` - Get bytes from the symmetric key (using getEncoded).
  - `PrivateKey privateKey = KeyConversion.privateKeyFromBytes(byte[] privKeyBytes)` - Get ECDH key pair private key by decoding the bytes into the original D value (the number defining the ECDH private key).
  - `PublicKey publicKey = KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes)` - Get ECDH key pair public key by decoding the bytes into the original Q value (the point defining the ECDH public key).
  - `SecretKey secretKey = KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes)` - Create a symmetric key using provided bytes.

- Random data generators.
  - `byte[] randomBytes = Generator.randomBytes(int N)` - Generate N random bytes using a secure random generator.
  - `String randomBase32 Generator.randomBase32String(int N)` - Generate string in Base32 encoding with N characters using a secure random generator.
  - `String uuid = Generator.randomUUID()` - Generate a new UUID level 4 and return it in string representation.
  - `String code = Generator.randomActivationCode()` - Generate a new `ACTIVATION_CODE`. See [Activation Code](./Activation-Code.md) for more details.
  - `String code = Generator.buildActivationCode(byte[10] randomBytes)` - Function return an activation code from given random data.

- Hashing and MAC functions.
  - `byte[] signature = Mac.hmacSha256(SecretKey key, byte[] message)` - Compute HMAC-SHA256 signature for given message using provided symmetric key.
  - `byte[] hash = Hash.sha256(byte[] original)` - Compute SHA256 hash of a given input.

- Password hashing.
  - `String hash = PasswordHash.hash(byte[] password)` - Compute Argon2 hash for given password. Hash is stored in Modular Crypt Format.
  - `boolean matches = PasswordHash.verify(byte[] password, String hash)` - Verify password against Argon2 hash stored in Modular Crypt Format.

- Utility functions.
  - `byte[] zeroBytes = ByteUtils.zeroBytes(int N)` - Generate buffer with N zero bytes.
  - `byte[] truncatedBytes = ByteUtils.truncate(byte[] bytes, int N)` - Get last N bytes of given byte array.
  - `int integer = ByteUtils.getInt(byte[4] bytes)` - Get integer from big endian encoded byte array.
  - `long value = ByteUtils.getLong(byte[8] bytes)` - Get long value from big endian encoded byte array.
  - `byte[] encodedShort = ByteUtils.encode(short n)` - encode number into sequence of bytes in big endian order.
  - `byte[] encodedInt = ByteUtils.encode(int n)` - encode number into sequence of bytes in big endian order.
  - `byte[] encodedLong = ByteUtils.encode(long n)` - encode number into sequence of bytes in big endian order.
  - `byte[] encodedString = ByteUtils.encode(String s)` - convert string into sequence of bytes with UTF-8 encoding.
  - `byte[] result = ByteUtils.concat(byte[]... args)` - concatenate multiple byte arrays:
    ```java
    byte[] concat(byte[]... args) {
        byte[] result = new byte[0];
        for (byte[] component : args) {
            if (component != null) {
                result = ByteUtils.concat(result, component);
            }
        }
        return result;
    }
    ```
  - `byte[] result = ByteUtils.concatWithSizes(byte[]... args)` - concatenate multiple byte array elements and prepend the length of each element:
    ```java
    byte[] concatWithSizes(byte[]... args) {
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
  - `byte[] result = ByteUtils.concatWithSizes(String... args)` - concatenate multiple string elements and prepend the length of each element: 
    ```java
    byte[] concatWithSizes(String... args) {
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
  - `byte[] result = ByteUtils.convert32Bto16B(byte[] bytes32)` - Converts 32b long byte array to 16b long array by xor-ing the first 16b with the second 16b, byte-by-byte.
  - `byte[] result = ByteUtils.subarray(byte[] bytes, int startIndex, int length)` - Obtain subarray of a byte array, starting with index `startIndex` with a given length.
  - `ByteUtils.copy(byte[] source, int sourcePosition, byte[] destination, int destinationPosition, int length)` - Copies `length` of bytes from the specified source array of bytes, beginning at the specified position, to the specified position of the destination array.

- Other functions.
  - `long timestamp = Time.getTimestamp()` - Get UNIX timestamp in milliseconds, since 1.1.1970