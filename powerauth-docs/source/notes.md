# Implementation Notes

## Used Cryptography

A PowerAuth 2.0 key exchange mechanism is based on **ECDH** key exchange algorithm with **P256r1 curve**. Additionally, an **ECDSA** (more specifically, **SHA256withECDSA** algorighm) is used for signing data sent from the service provider using a provider's Master Private Key. After a successful key exchange, both client and server have a shared master secret and they establish a shared counter initialized on 0 (later on, each signature attempt increments this counter). The PowerAuth 2.0 signature is computed using data, shared master secret and counter using the **HMAC** algorithm.

## KDF Algorithm

KDF (Key Derivation Function) is an algorithm used for deriving a secret key from a master secret key using a pseudo-random function. In case of PowerAuth 2.0 protocol, following implementation is used:

- `// KDF(KEY_MASTER, INDEX) => KEY_SECRET_index`
- `byte[] KEY_SECRET_index = AES(index ⊕ 0x0000..., KEY_MASTER)`

## Activation ID

The `ACTIVATION_ID` must be in principle long, universally unique, random and with a temporary validity. UUID level 4 is therefore the selected format of this ID.

	DO {
		ACTIVATION_ID = UUID_GEN()
		COUNT = SELECT COUNT(\*) FROM ACTIVATION WHERE ACTIVATION.ID = ACTIVATION_ID
	} WHILE (COUNT > 0);

Example of activation ID:

	c564e700-7e86-4a87-b6c8-a5a0cc89683f

_Note: A single UUID for an activation in CREATED state must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most)._

Since the UUID is too long and inconvenient for practical applications, `ACTIVATION_ID` is exchanged between client and server automatically, using `ACTIVATION_ID_SHORT` - a shorter and more convenient identifier of an activation. This is the identifier user can rewrite or scan via the QR code.  `ACTIVATION_ID_SHORT` is a Base32 string, 2x 5 characters:

	DO {
		ACTIVATION_ID_SHORT = BASE32_RANDOM_STRING(5) + "-" + BASE32_RANDOM_STRING(5)
		COUNT = SELECT COUNT(\*) FROM ACTIVATION WHERE (ACTIVATION.STATE = 'CREATED' OR ACTIVATION.STATE = 'OTP_USED') AND ACTIVATION.ID_SHORT = ACTIVATION_ID_SHORT
	} WHILE (COUNT > 0);


Example of short activation ID:

	XDA57-24TBC

## Application ID and Application Secret

In order to explicitly bind a client application with the cryptography, an application ID and application secret are introduced. Both values follow the same format - 16B encoded as Base64, application ID must be unique.

Both identifiers are embedded in the PowerAuth 2.0 Client application (for example, defined as a constants in the source code).

Application ID is sent with every PowerAuth Signature as `pa_applicationId`.

Application secret is a part of the PowerAuth signature (sent in `pa_signature`), it enters the algorithm in final HMAC_SHA256 as a part of the DATA.

## Activation OTP

The `ACTIVATION_OTP` is a Base32 string, 2 x 5 characters:

	ACTIVATION_OTP = BASE32_RANDOM_STRING(5) + "-" + BASE32_RANDOM_STRING(5)

Example of activation OTP:

	TB24C-A57XD

This format matches the `ACTIVATION_ID_SHORT` format.

_Note: A single `ACTIVATION_OTP` must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most). Also, the activation OTP can be used only once - the moment client application sends and receives the encrypted public keys, it must be marked as "already used"._

## Entering values in client applications

Entering `ACTIVATION_ID_SHORT`, `ACTIVATION_OTP` and `ACTIVATION_SIGNATURE` can be expedited for example by using QR code for the storage. PowerAuth 2.0 defines using following format of information:

	${ACTIVATION_ID_SHORT}-${ACTIVATION_OTP}#${ACTIVATION_SIGNATURE}

Example concatenated string:

	XDA57-24TBC-TB24C-A57XD#1234567890

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
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
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
    Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
    ecdsaSign.initSign(privateKey);
    ecdsaSign.update(bytes);
    byte[] signature = ecdsaSign.sign();
    return signature;
}
```

To verify the signature, following code is used:

```java
public boolean isSignatureCorrectForBytes(byte[] bytes, byte[] signature, PublicKey publicKey)
    Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
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
		<td>`KEY_DEVICE_PRIVATE`</td>
		<td>ECDH - private key</td>
		<td>Generated on client to allow construction of `KEY_MASTER_SECRET`</td>
	</tr>
	<tr>
		<td>`KEY_DEVICE_PUBLIC`</td>
		<td>ECDH - public key</td>
		<td>Generated on client to allow construction of `KEY_MASTER_SECRET`</td>
	</tr>
	<tr>
		<td>`KEY_SERVER_PRIVATE`</td>
		<td>ECDH - private key</td>
		<td>Generated on server to allow construction of `KEY_MASTER_SECRET`</td>
	</tr>
	<tr>
		<td>`KEY_SERVER_PUBLIC`</td>
		<td>ECDH - public key</td>
		<td>Generated on server to allow construction of `KEY_MASTER_SECRET`</td>
	</tr>
	<tr>
		<td>`KEY_SERVER_MASTER_PRIVATE`</td>
		<td>ECDH - private key</td>
		<td>Stored on server, used to assure authenticity of `KEY_DEVICE_PUBLIC` while transferring from server to client</td>
	</tr>
	<tr>
		<td>`KEY_SERVER_MASTER_PUBLIC`</td>
		<td>ECDH - public key</td>
		<td>Stored on client, used to assure authenticity of `KEY_DEVICE_PUBLIC` while transferring from server to client</td>
	</tr>
	<tr>
		<td>`ACTIVATION_OTP`</td>
		<td>Random OTP</td>
		<td>A 16b random OTP generated during activation, AES encrypts/decrypts data sent from server to client and vice versa</td>
	</tr>
	<tr>
		<td>`KEY_MASTER_SECRET`</td>
		<td>ECDH - pre-shared</td>
		<td>A key deduced using ECDH derivation, `KEY_MASTER_SECRET` = (`KEY_DEVICE_PRIVATE`,`KEY_SERVER_PUBLIC`) = (`KEY_SERVER_PRIVATE`,`KEY_DEVICE_PUBLIC`)</td>
	</tr>
	<tr>
		<td>`KEY_SIGNATURE`</td>
		<td>KDF derived key from `KEY_MASTER_SECRET`</td>
		<td>A key deduced using KDF derivation with INDEX = 1, `KEY_SIGNATURE` = KDF(`KEY_MASTER_SECRET`, 1), used for subsequent request signing</td>
	</tr>
	<tr>
		<td>`KEY_TRANSPORT`</td>
		<td>KDF derived key from `KEY_MASTER_SECRET`</td>
		<td>A key deduced using KDF derivation with INDEX = 2, `KEY_TRANSPORT` = KDF(`KEY_MASTER_SECRET`, 2), used for encrypted data transport</td>
	</tr>
</table>
