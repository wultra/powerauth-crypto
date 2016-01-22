# Implementation Notes

Following implementation notes use simplified Java code with definitions from the "Definitions" section or a simple pseudo-code to get the point across quicker.

## Used Cryptography

A PowerAuth 2.0 key exchange mechanism is based on **ECDH** key exchange algorithm with **P256r1 curve**. Additionally, an **ECDSA** (more specifically, **SHA256withECDSA** algorighm) is used for signing data sent from the service provider using a provider's Master Private Key. After a successful key exchange, both client and server have a shared master secret and they establish a shared counter initialized on 0 (later on, each signature attempt increments this counter). The PowerAuth 2.0 signature is computed using data, shared master secret and counter using the **HMAC** algorithm.

## KDF Algorithm

KDF (Key Derivation Function) is an algorithm used for deriving a secret key from a master secret key using a pseudo-random function. In case of PowerAuth 2.0 protocol, following implementation is used:

```java
public SecretKey kdfDeriveSecretKey(SecretKey secret, long index) {
    byte[] bytes = ByteBuffer.allocate(16).putLong(index).array();
    byte[] iv = new byte[16];
    byte[] encryptedBytes = AES.encrypt(bytes, iv, secret);
    return new KeyConversion.secretKeyFromBytes(encryptedBytes);
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

Since the UUID is too long and inconvenient for practical applications, `ACTIVATION_ID` is exchanged between client and server automatically, using `ACTIVATION_ID_SHORT` - a shorter and more convenient identifier of an activation. This is the identifier user can rewrite or scan via the QR code.  `ACTIVATION_ID_SHORT` is a Base32 string, 2x 5 characters:

```sql
DO {
		ACTIVATION_ID_SHORT = BASE32_RANDOM_STRING(5) + "-" + BASE32_RANDOM_STRING(5)
		COUNT = SELECT COUNT(*) FROM ACTIVATION WHERE (ACTIVATION.STATE = 'CREATED' OR ACTIVATION.STATE = 'OTP_USED') AND ACTIVATION.ID_SHORT = ACTIVATION_ID_SHORT
} WHILE (COUNT > 0);
```

Example of short activation ID:

```
XDA57-24TBC
```

## Application ID and Application Secret

In order to explicitly bind a client application with the cryptography, an application ID and application secret are introduced. Both values follow the same format - 16B encoded as Base64, application ID must be unique.

Both identifiers are embedded in the PowerAuth 2.0 Client application (for example, defined as a constants in the source code).

Application ID is sent with every PowerAuth Signature as `pa_applicationId`.

Application secret is a part of the PowerAuth signature (sent in `pa_signature`), it enters the algorithm in final HMAC_SHA256 as a part of the DATA.

## Activation OTP

The `ACTIVATION_OTP` is a Base32 string, 2 x 5 characters:

```
ACTIVATION_OTP = BASE32_RANDOM_STRING(5) + "-" + BASE32_RANDOM_STRING(5)
```

Example of activation OTP:

```
TB24C-A57XD
```

This format matches the `ACTIVATION_ID_SHORT` format.

_Note: A single `ACTIVATION_OTP` must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most). Also, the activation OTP can be used only once - the moment client application sends and receives the encrypted public keys, it must be marked as "already used"._

## Entering values in client applications

Entering `ACTIVATION_ID_SHORT`, `ACTIVATION_OTP` and `ACTIVATION_SIGNATURE` can be expedited for example by using QR code for the storage. PowerAuth 2.0 defines using following format of information:

```
${ACTIVATION_ID_SHORT}-${ACTIVATION_OTP}#${ACTIVATION_SIGNATURE}
```

Example concatenated string:

```
XDA57-24TBC-TB24C-A57XD#1234567890
```

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
		// we assume BouncyCastle provider
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

Server sends it's encrypted public key `C_KEY_SERVER_PUBLIC` to the client with a signature `C_KEY_SERVER_PUBLIC`. This signature is created using the server's "Master Private Key" `KEY_SERVER_MASTER_PRIVATE`. Since the same key is used for all activations, the "latent private key fingerprints" may accumulate over the time, making it simpler to attack the private key. Therefore, it is important to select the proper trusted certification authority to issue the keys and renew the key after certain time period. Usually, this also requires timely update of the clients that bundle the "Master Public Key".

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

## List of Keys Used in the Process

Following keys are used for the PowerAuth cryptography scheme.

<table>
	<tr>
		<th>name</th>
		<th>created as</th>
		<th>purpose</th>
	</tr>
	<tr>
		<td><code>KEY_DEVICE_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Generated on client to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_DEVICE_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Generated on client to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Generated on server to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Generated on server to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_MASTER_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Stored on server, used to assure authenticity of <code>KEY_DEVICE_PUBLIC</code> while transferring from server to client</td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_MASTER_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Stored on client, used to assure authenticity of <code>KEY_DEVICE_PUBLIC</code> while transferring from server to client</td>
	</tr>
	<tr>
		<td><code>ACTIVATION_OTP</code></td>
		<td>Random OTP</td>
		<td>A 16b random OTP generated during activation, AES encrypts/decrypts data sent from server to client and vice versa</td>
	</tr>
	<tr>
		<td><code>KEY_MASTER_SECRET</code></td>
		<td>ECDH - pre-shared</td>
		<td>A key deduced using ECDH derivation, <code>KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE,KEY_SERVER_PUBLIC) = ECDH.phase(KEY_SERVER_PRIVATE,KEY_DEVICE_PUBLIC)</code></td>
	</tr>
	<tr>
		<td><code>KEY_SIGNATURE_POSSESSION</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A signing key associated with the possession, factor deduced using KDF derivation with <code>INDEX = 1</code>, <code>KEY_SIGNATURE_POSSESSION = KDF.expand(KEY_MASTER_SECRET, 1)</code>, used for subsequent request signing</td>
	</tr>
  <tr>
		<td><code>KEY_SIGNATURE_KNOWLEDGE</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key associated with the knowledge factor, deduced using KDF derivation with <code>INDEX = 2</code>, <code>KEY_SIGNATURE_KNOWLEDGE = KDF.expand(KEY_MASTER_SECRET, 2)</code>, used for subsequent request signing</td>
	</tr>
  <tr>
		<td><code>KEY_SIGNATURE_BIOMETRY</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key associated with the biometry factor, deduced using KDF derivation with <code>INDEX = 3</code>, <code>KEY_SIGNATURE_BIOMETRY = KDF.expand(KEY_MASTER_SECRET, 3)</code>, used for subsequent request signing</td>
	</tr>
	<tr>
		<td><code>KEY_TRANSPORT</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key deduced using KDF derivation with <code>INDEX = 1000</code>, <code>KEY_TRANSPORT = KDF.expand(KEY_MASTER_SECRET, 1000)</code>, used for encrypted data transport</td>
	</tr>
	<tr>
		<td><code>KEY_ENCRYPTION_VAULT</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key deduced using KDF derivation with <code>INDEX = 2000</code>, <code>KEY_ENCRYPTION_VAULT = KDF.expand(KEY_MASTER_SECRET, 2000)</code>, used for encrypting a vault that stores the secret data, such as <code>KEY_DEVICE_PRIVATE</code>.</td>
	</tr>
  <tr>
		<td><code>KEY_ENCRYPTION_VAULT_TRANSPORT</code></td>
		<td>KDF derived key from <code>KEY_TRANSPORT</code> using <code>CTR</code> as index.</td>
		<td>A one-time key used for encrypted transport of the key vault encryption, deduced using KDF derivation with <code>INDEX = CTR</code>, <code>KEY_TRANSPORT = KDF.expand(KEY_MASTER_SECRET, CTR)</code></td>
	</tr>
</table>
