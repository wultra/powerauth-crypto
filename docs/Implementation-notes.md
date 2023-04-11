# Implementation Notes

Following implementation notes use simplified Java code with definitions from the "Definitions" section or a simple pseudo-code to get the point across quicker.

## Used Cryptography

A PowerAuth key exchange mechanism is based on **ECDH** key exchange algorithm with **P256r1 curve**. Additionally, an **ECDSA** (more specifically, **SHA256withECDSA** algorighm) is used for signing data sent from the service provider using a provider's Master Private Key. After a successful key exchange, both client and server have a shared master secret and they establish a shared counter initialized on 0. Later on, each signature attempt increments this counter. A related hash-based counter is initialized as well with a random value and it is updated with each signature attempt. The PowerAuth signature is computed using data, shared master secret and counter using the **HMAC** algorithm.

## Key Derivation Functions

KDF (Key Derivation Function) is an algorithm used for deriving a secret key from a master secret key using a pseudo-random function. PowerAuth uses three types of functions for KDF:

- **KDF** - AES-based KDF function. Works by encrypting fixed `long` index with a random secret master key. This function is handy for situations where developer selects the function index. A human readable index, such as "1", "2", or "1000" can be selected for key derivation.
- **KDF_INTERNAL** - HMAC-SHA256-based KDF function. Works by computing HMAC-SHA256 of provided `byte[]` index with a random secret master key. This function is used in internal algorithm workings, in situations where readability of the index is not important at all.
- **PBKDF2** - Standard algorithm for deriving long keys from short passwords. This function is considered a standard KDF and it is used only for deriving base key from the user entered password. Since it has no major impact on PowerAuth cryptography, we will not elaborate about this KDF in more details.

### KDF Description

```java
public SecretKey kdfDeriveSecretKey(SecretKey secret, long index) {
    byte[] bytes = ByteBuffer.allocate(16).putLong(index).array();
    byte[] iv = new byte[16];
    byte[] newKeyBytes = AES.encrypt(bytes, iv, secret);
    return KeyConversion.secretKeyFromBytes(newKeyBytes);
}
```

### KDF_INTERNAL Description

```java
public SecretKey deriveSecretKeyHmac(SecretKey secret, byte[] index) {
    byte[] derivedKey = Mac.hmacSha256(secret, index);
    byte[] newKeyBytes = ByteUtil.convert32Bto16B(derivedKey32);
    return KeyConversion.secretKeyFromBytes(newKeyBytes);
}
```

For the purpose of completeness, the `ByteUtil.convert32Bto16B()` function is implemented in a following manner:

```java
public byte[] ByteUtil.convert32Bto16B(byte[] original) {
    if (original.length != 32) {
        return null; // error state
    }
    byte[] resultSecret = new byte[16];
    for (int i = 0; i < 16; i++) {
        resultSecret[i] = (byte) (original[i] ^ original[i + 16]);
    }
    return resultSecret;
}
```

## Activation ID

The `ACTIVATION_ID` must be in principle long, universally unique, random and with a temporary validity. UUID level 4 is therefore the selected format of this ID.

```sql
DO {
    ACTIVATION_ID = UUID_GEN()
    COUNT = SELECT COUNT(*) FROM ACTIVATION WHERE ACTIVATION.ID = ACTIVATION_ID
} WHILE (COUNT > 0);
```

Example of activation ID:

```
c564e700-7e86-4a87-b6c8-a5a0cc89683f
```

_Note: A single UUID for an activation in CREATED state must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most)._

Since the UUID is too long and inconvenient for practical applications, `ACTIVATION_ID` is exchanged between client and server automatically, using `ACTIVATION_CODE` - a shorter and more convenient identifier of an activation. This is the identifier user can rewrite or scan via the QR code. The next chapter explains more details about the code.


## Activation Code

The `ACTIVATION_CODE` is a Base32 string 4 x 5 characters. The code is randomly generated and contains CRC-16 checksum which can detect a few typing errors in the code. For more details, check a [dedicated document](./Activation-Code.md) about the code construction and validation. 

A single `ACTIVATION_CODE` must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most). Also, the activation code can be used only once - the moment client application sends and receives the encrypted public keys, it must be marked as "already used".

```sql
DO {
    ACTIVATION_CODE = Generator.randomActivationCode()
    COUNT = SELECT COUNT(*) FROM ACTIVATION WHERE (ACTIVATION.STATE = 'CREATED' OR ACTIVATION.STATE = 'PENDING_COMMIT') AND ACTIVATION.CODE = ACTIVATION_CODE
} WHILE (COUNT > 0);
```

Example of activation code:

```
MMMMM-MMMMM-MMMMM-MUTOA
```

## Application ID and Application Secret

In order to explicitly bind a client application with the cryptography, an application ID and application secret are introduced. Both values follow the same format - 16B encoded as Base64, application ID must be unique.

Both identifiers are embedded in the PowerAuth Client application (for example, defined as a constants in the source code).

Application ID is sent with every PowerAuth Signature as `pa_applicationId`.

Application secret is a part of the PowerAuth signature (sent in `pa_signature`), it enters the algorithm in final HMAC_SHA256 as a part of the DATA.

## Entering Values in Client Application

Entering `ACTIVATION_CODE` and `ACTIVATION_SIGNATURE` can be expedited for example by using QR code for the storage. PowerAuth defines using following format of information:

```
${ACTIVATION_CODE}#${ACTIVATION_SIGNATURE}
```

Example concatenated string:

```
MMMMM-MMMMM-MMMMM-MUTOA#1234567890
```

*You can also check [Activation Code](./Activation-Code.md) document to get a more details about an activation code.*

## Generating Key Pairs

The device and server keys are generated using ECDH algorithm with P256 curve:

```java
public KeyPair generateKeyPair() {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC"); // we assume BouncyCastle provider
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = kpg.generateKeyPair();
    return kp;
}
```
## Shared Key Derivation (ECDH)

Shared key `KEY_MASTER_SECRET` is generated using following algorithm (ECDH):

```java
public SecretKey generateSharedKey(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException {
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC"); // we assume BouncyCastle provider
    keyAgreement.init((Key) privateKey, new ECGenParameterSpec("secp256r1"));
    keyAgreement.doPhase(publicKey, true);
    final byte[] sharedSecret = keyAgreement.generateSecret();
    byte[] resultSecret = new byte[16];
    for (int i = 0; i < 16; i++) {
        resultSecret[i] = (byte) (sharedSecret[i] ^ sharedSecret[i + 16]);
    }
    return convertBytesToSharedSecretKey(resultSecret);
}
```

## Secure Network Communication

All communication should be carried over a properly secured channel, such as HTTPS with correct server configuration and certificate issued with a trusted certificate authority. Client may implement certificate pinning to achieve better transport level security.

## Lifecycle of the "Master key pair"

Server sends it's encrypted public key `C_KEY_SERVER_PUBLIC` to the client with a signature `SERVER_DATA_SIGNATURE`. This signature is created using the server's "Master Private Key" `KEY_SERVER_MASTER_PRIVATE`. Since the same key is used for all activations, the "latent private key fingerprints" may accumulate over the time, making it simpler to attack the private key. Therefore, it is important to select the proper trusted certification authority to issue the keys and renew the key after certain time period. Usually, this also requires timely update of the clients that bundle the "Master Public Key".

## Signing Data Using Master Private Key

The master key pair is generated using the same algorithm as normal key pair, see above (with P256 curve).

In order to generate the signature for given bytes (obtained from string by conversion using UTF-8 encoding), following code is used:

```java
public byte[] signatureForBytes(byte[] bytes, PrivateKey privateKey) {
    Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC"); // we assume BouncyCastle provider
    ecdsaSign.initSign(privateKey);
    ecdsaSign.update(bytes);
    byte[] signature = ecdsaSign.sign();
    return signature;
}
```

To verify the signature, following code is used:

```java
public boolean isSignatureCorrectForBytes(byte[] bytes, byte[] signature, PublicKey publicKey)
    Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC"); // we assume BouncyCastle provider
    ecdsaVerify.initVerify(publicKey);
    ecdsaVerify.update(bytes);
    boolean result = ecdsaVerify.verify(signature);
    return result;
}
```
