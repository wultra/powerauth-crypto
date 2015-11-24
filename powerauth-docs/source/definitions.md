# Basic definitions

The goal of this chapter is to define used functions related to cryptography and data manipulation. The definitions crafted in this chapter are then used in pseudo-codes in documentation. You can learn more about actual implementation of following functions in the "Implementation Notes" section.

## Cryptographic functions

Following basic cryptography algorithms and parameters are used in the PowerAuth 2.0 cryptography description:

- **AES** - A symmetric key encryption algorithm, uses CBC mode and PKCS5 padding. It defines two operations:
	- `byte[] encrypted = AES.encrypt(byte[] original, byte[] iv, SecretKey key)` - encrypt bytes using symmetric key with given initialization vector.
	- `byte[] original = AES.decrypt(byte[] encrypted, byte[] iv, SecretKey key)` - decrypt bytes using symmetric key with given initialization vector.
- **PBKDF2** - An algorithm for key stretching, converts a short password into long key by performing repeated hash iteration on the original data, HMAC-SHA1 algorithm is used for a pseudo-random function. Implementations must make sure resulting key is converted in format usable by AES algorithm. One method is defined for this algorithm:
	- `SharedKey expandedKey = PBKDF2.expand(char[] password, byte[] salt, long iterations, long lengthInBits)` - stretch the password using given number of iterations to achieve key of given length in bits, use given salt.
- **ECDSA** - An algorithm for elliptic curve based signatures, uses SHA256 hash algorithm. It defines two operations:
	- `byte[] signature = ECDSA.sign(byte[] data, PrivateKey privateKey)` - compute signature of given data and private key.
	- `boolean isValid = ECDSA.verify(byte[] data, byte[] signature, PublicKey publicKey)` - verify the signature for given data using a given public key.
- **ECDH** - An algorithm for elliptic curve with Diffie-Helman key exchange, uses P256r1 curve. We define single operation on ECDH, a symmetric key deduction between parties A and B:
	- `SecretKey secretKey = ECDH.phase(PrivateKey privateKeyA, PublicKey publicKeyB)`
- **KDF** - A key derivation function used to derive a symmetric key with specific "index" from a given master key. Uses AES algorithm with zero initialization vector to derive the new key in following way: `index` is converted to bytes, XORed with a 16 byte long zero array (to get 16 byte long array with bytes from the index) and AES encrypted using provided symmetric key `masterKey`.
	- `SecretKey derivedKey = KDF.derive(SecretKey masterKey, long index)`

## Helper functions

These functions are used in the pseudo-codes:

- Key generators.
	- `KeyPair keyPair = KeyGenerator.randomKeyPair()` - Generate a new ECDH key pair using P256r1 elliptic curve.

- Key conversion utilities.
	- `byte[] privateKeyBytes = KeyConversion.getBytes(PrivateKey privKey)` - Get bytes from the ECDH key pair private key by encoding the Q value (the number defining the ECDH private key).
	- `byte[] publicKeyBytes = KeyConversion.getBytes(PublicKey pubKey)` - Get bytes from the ECDH key pair public key by encoding the D value (the point defining the ECDH public key).
	- `byte[] secretKeyBytes = KeyConversion.getBytes(SecretKey secretKey)` - Get bytes from the symmetric key (using getEncoded).
	- `PrivateKey privateKey = KeyConversion.privateKeyFromBytes(byte[] privKeyBytes)` - Get ECDH key pair private key by decoding the bytes into the original Q value (the number defining the ECDH private key).
	- `PublicKey publicKey = KeyConversion.publicKeyFromBytes(byte[] pubKeyBytes)` - Get ECDH key pair public key by decoding the bytes into the original D value (the point defining the ECDH public key).
	- `SecretKey secretKey = KeyConversion.secretKeyFromBytes(byte[] secretKeyBytes)` - Create a symmetric key using provided bytes.

- Random data generators.
	- `byte[] randomBytes = Generator.randomBytes(int N)` - Generate N random bytes using a secure random generator.
	- `String randomBase32 Generator.randomBase32String(int N)` - Generate string in Base32 encoding with N characters using a secure random generator.
	- `String uuid = Generator.randomUUUD()` - Generate a new UUID level 4 and return it in string representation.

- Hashing and MAC functions.
	- `byte[] signature = Mac.hmacSha256(SharedKey key, byte[] message)` - Compute HMAC-SHA256 signature for given message using provided symmetric key.
	- `byte[] hash = Hash.sha256(byte[] original)` - Compute SHA256 hash of a given input.

- Utility functions.
	- `byte[] zeroBytes = ByteUtils.zeroBytes(int N)` - Generate buffer with N zero bytes.
	- `byte[] truncatedBytes = ByteUtils.truncate(byte[] bytes, int N)` - Get last N bytes of given byte array.
	- `int integer = ByteUtils.getInt(byte[4] bytes)` - Get integer from 4 byte long byte array.
