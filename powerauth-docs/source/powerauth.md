# PowerAuth 2.0 Specification

PowerAuth 2.0 is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth 2.0 protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## Basic definitions

### Cryptographic functions

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

### Helper functions

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

# PowerAuth Activation

In PowerAuth 2.0, both client and server must first share the same shared master secret `KEY_MASTER_SECRET`. The `KEY_MASTER_SECRET` is a symmetric key that is used as a base for deriving the further purpose specific shared secret keys. These derived keys are then used for an HTTP request signing. In order to establish this shared master secret, a secure key exchange (or "activation") must take a place.

## Activation Actors

Following components play role in activation:

- **PowerAuth 2.0 Client** - A client "to be activated" application, that implements PowerAuth 2.0 protocol. A good example of a typical PowerAuth 2.0 Client can be a mobile banking application.
- **Master Front-End Application** - An application that initiates the activation process and helps the PowerAuth 2.0 Client start the key exchange algorithm. Example of Master Front-End Application can be an Internet banking.
- **Intermediate Server Application** - A front-end facing server application (or a set of applications, that we currently view as a single unified system, for the sake of simplicity) that is deployed in demilitarized zone in order to accommodate a communication between PowerAuth 2.0 Client, Master Front-End Application and PowerAuth 2.0 Server. A good example of Intermediate Server Application is a mobile banking RESTful API server.
- **PowerAuth 2.0 Server** - A server application hidden deep in secure infrastructure, stores activation records, or verifies the request signatures. This application provides services for Intermediate Server Application to implement the PowerAuth 2.0 protocol. An example of a PowerAuth 2.0 Server is a bank identity management system.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/api-big-picture.png" width="100%"/>

## Activation States

Record associated with given PowerAuth 2.0 keys transits between following states during it's lifecycle:

- **CREATED** - The activation record is created but it was not activated yet.
- **OTP_USED** - The activation record is created and activation OTP was already used, but the activation record was not activated yet.
- **ACTIVE** - The activation record is created and active, ready to be used for generating signatures.
- **BLOCKED** - The activation record is blocked and cannot be used for generating signatures. It can be renewed and activated again.
- **REMOVED** - The activation record is permanently blocked - cannot be used for generating signatures or renewed.

After the key exchange is initiated, an activation record is created in the database in the CREATED state. In subsequent requests, client application must complete the activation. The system that initiated the activation (such as the web interface) must push the status of the token to the ACTIVE state before it can be used.

Following diagram shows transitions between activation states in more detail:

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-lifecycle.png" width="100%"/>

## Activation User Flow

From the user perspective, PowerAuth 2.0 activation is performed as a sequence of steps in PowerAuth 2.0 Client and Master Front-End Application. Following steps (with possible UI / UX alterations) must be performed:

### Master Front-End Application

Following diagram shows example steps in Master Front-End Application - imagine the Internet banking as an example application.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-master-frontend-activation.png" width="100%"/>

### PowerAuth 2.0 Client

Following diagram shows example steps in PowerAuth 2.0 Client - imagine the Mobile banking as an example application.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-client-activation.png" width="100%"/>


## Activation Flow - Sequence Diagram

The sequence diagram below explains the PowerAuth 2.0 key exchange. It shows how PowerAuth 2.0 Client, Intermediate Server Application, Master Front-End Application and PowerAuth 2.0 Server play together in order to establish a shared secret between the client application and PowerAuth Server.

//TODO: Review the diagram
<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth.png" width="100%"/>

## Activation Flow - Description

To describe the steps more precisely, the activation process is performed in following steps:

1. Master Front-End Application requests a new activation for a given user.

1. PowerAuth 2.0 Server generates an `ACTIVATION_ID`, `ACTIVATION_ID_SHORT`, a key pair `(KEY_SERVER_PRIVATE, KEY_SERVER_PUBLIC)` and `ACTIVATION_OTP`. Server also optionally computes a signature `ACTIVATION_SIGNATURE` of `ACTIVATION_ID_SHORT` and `ACTIVATION_OTP` using servers master private key `KEY_SERVER_MASTER_PRIVATE`.

	- `String ACTIVATION_ID = Generator.randomUUID()`
	- `String ACTIVATION_ID_SHORT = Generator.randomBase32String(5) + "-" + Generator.randomBase32String(5)` (must be unique among records in CREATED and OTP_USED states)
	- `String ACTIVATION_OTP = Generator.randomBase32String(5) + "-" + Generator.randomBase32String(5)`
	- `KeyPair keyPair = KeyGenerator.randomKeyPair()`
	- `PrivateKey KEY_SERVER_PRIVATE = keyPair.getPrivate()`
	- `PublicKey KEY_SERVER_PUBLIC = keyPair.getPublic()`
	- `byte[] DATA = (ACTIVATION_ID_SHORT + "-" + ACTIVATION_OTP).getBytes("UTF-8")`
	- `byte[] ACTIVATION_SIGNATURE = ECDSA.sign(DATA, KEY_SERVER_MASTER_PRIVATE)`

1. Record associated with given `ACTIVATION_ID` is now in `CREATED` state.

1. Master Front-End Application receives an `ACTIVATION_ID_SHORT`, `ACTIVATION_OTP` and `ACTIVATION_SIGNATURE` (optional) and displays these information visually in the front-end so that a user can rewrite them in PowerAuth 2.0 Client.

1. User enters `ACTIVATION_ID_SHORT`, `ACTIVATION_OTP` and `ACTIVATION_SIGNATURE` (optional) in the PowerAuth 2.0 Client, for example using manual entry or by scanning a QR code with activation data.

1. (optional) PowerAuth 2.0 Client verifies `ACTIVATION_SIGNATURE` against `ACTIVATION_ID_SHORT` and `ACTIVATION_OTP` using `KEY_SERVER_MASTER_PUBLIC` and if the signature matches, it proceeds.

	- `byte[] DATA = (ACTIVATION_ID_SHORT + "-" + ACTIVATION_OTP).getBytes("UTF-8")`
	- `boolean isOK = ECDSA.verify(DATA, KEY_SERVER_MASTER_PUBLIC)`

1. PowerAuth 2.0 Client generates its key pair `(KEY_DEVICE_PRIVATE, KEY_DEVICE_PUBLIC)`.

	- `KeyPair keyPair = KeyGenerator.randomKeyPair()`
	- `PrivateKey KEY_DEVICE_PRIVATE = keyPair.getPrivate()`
	- `PublicKey KEY_DEVICE_PUBLIC = keyPair.getPublic()`

1. PowerAuth 2.0 Client sends a request with an `ACTIVATION_ID_SHORT`, `ACTIVATION_NONCE` (used as an initialization vector for AES encryption) and `C_KEY_DEVICE_PUBLIC` to the PowerAuth 2.0 Server (via Intermediate Server Application).

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `byte[] ACTIVATION_NONCE = Generator.randomBytes(16)`
	- `byte[] keyPublicBytes = KeyConversion.getBytes(KEY_DEVICE_PUBLIC)`
	- `byte[] C_KEY_DEVICE_PUBLIC = AES.encrypt(, ACTIVATION_NONCE, KEY_ENCRYPTION_OTP)`

1. PowerAuth 2.0 Server decrypts and stores the public key at given record.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `byte[] keyPublicBytes = AES.decrypt(C_KEY_DEVICE_PUBLIC, ACTIVATION_NONCE, KEY_ENCRYPTION_OTP)`
	- `PublicKey KEY_DEVICE_PUBLIC = KeyConversion.publicKeyFromBytes(keyPublicBytes)`

1. PowerAuth 2.0 Server changes the record status to `OTP_USED`

1. PowerAuth 2.0 Server responds with `ACTIVATION_ID`, `C_KEY_SERVER_PUBLIC`, `KEY_EPHEMERAL_PUBLIC` and `C_KEY_SERVER_PUBLIC_SIGNATURE`.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `KeyPair keyPair = KeyGenerator.randomKeyPair()`
	- `PrivateKey KEY_EPHEMERAL_PRIVATE = keyPair.getPrivate()`
	- `PublicKey KEY_EPHEMERAL_PUBLIC = keyPair.getPublic()`
	- `SecretKey EPH_KEY = ECDH.phase(KEY_EPHEMERAL_PRIVATE, KEY_DEVICE_PUBLIC)`
	- `byte[] EPHEMERAL_NONCE = Generator.randomBytes(16)`
	- `byte[] keyPublicBytes = KeyConversion.getBytes(KEY_SERVER_PUBLIC)`
	- `byte[] C_KEY_SERVER_PUBLIC = AES.encrypt(AES.encrypt(keyPublicBytes, EPHEMERAL_NONCE, KEY_ENCRYPTION_OTP), EPHEMERAL_NONCE, EPH_KEY)`
	- `byte[] C_KEY_SERVER_PUBLIC_SIGNATURE = ECDSA.sign(C_KEY_SERVER_PUBLIC, KEY_SERVER_MASTER_PRIVATE)`

1. PowerAuth 2.0 Client receives an `ACTIVATION_ID`, `C_KEY_SERVER_PUBLIC`, `KEY_EPHEMERAL_PUBLIC` and `C_KEY_SERVER_PUBLIC_SIGNATURE` and if the signature matches the data, it retrieves `KEY_SERVER_PUBLIC`.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `boolean isSignatureOK = ECDSA.verify(C_KEY_SERVER_PUBLIC, KEY_SERVER_MASTER_PRIVATE)`
	- `SecretKey EPH_KEY = ECDH.phase(KEY_DEVICE_PRIVATE, KEY_EPHEMERAL_PUBLIC)`
	- `byte[] keyPublicBytes = AES.decrypt(AES.decrypt(C_KEY_SERVER_PUBLIC, EPHEMERAL_NONCE, KEY_ENCRYPTION_OTP), EPHEMERAL_NONCE, PH_KEY)`
	- `PublicKey KEY_SERVER_PUBLIC = KeyConversion.publicKeyFromBytes(keyPublicBytes)`

1. Both PowerAuth 2.0 Client and PowerAuth 2.0 Server set `CTR = 0` for given `ACTIVATION_ID`.

1. (optional) PowerAuth 2.0 Client displays `H_K_DEVICE_PUBLIC`, so that a user can verify the device public key correctness by entering `H_K_DEVICE_PUBLIC` in the Master Front-End Application (Master Front-End Application sends `H_K_DEVICE_PUBLIC` for verification to PowerAuth 2.0 Server via Intermediate Server Application).

	- `byte[] truncatedBytes = ByteUtils.truncate(Hash.sha256(KeyConversion.getBytes(K_DEVICE_PUBLIC_BYTES), 4)`
	- `int H_K_DEVICE_PUBLIC = ByteUtils.getInt(truncatedBytes) & 0x7FFFFFFF) % (10 ^ 8)`
	- _Note: Client and server should check the client's public key fingerprint before the shared secret established by the key exchange is considered active. This is necessary so that user can verify the exchanged information in order to detect the MITM attack. (Displaying fingerprint of the server key is not necessary, since the server's public key is signed using server's private master key and encrypted with activation OTP and server public key)._

1. PowerAuth 2.0 Client uses `KEY_DEVICE_PRIVATE` and `KEY_SERVER_PUBLIC` to deduce `KEY_MASTER_SECRET` using ECDH.

	- `KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE, KEY_SERVER_PUBLIC)`

1. PowerAuth 2.0 Server uses `KEY_DEVICE_PUBLIC` and `KEY_SERVER_PRIVATE` to deduce `KEY_MASTER_SECRET` using ECDH.

		- `KEY_MASTER_SECRET = ECDH.phase(KEY_SERVER_PRIVATE, KEY_DEVICE_PUBLIC)`

1. Master Front-End Application allows completion of the activation - for example, it may ask user to enter a code delivered via an SMS message. Master Front-End Application technically commits the activation by calling PowerAuth 2.0 Server (via Intermediate Server Application).

1. Record associated with given `ACTIVATION_ID` is now in `ACTIVE` state.

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

# PowerAuth Signature

While PowerAuth 2.0 can be used for signing any type of data, the main objective of the protocol is to allow signing of HTTP requests sent to the server in order to prove consistency, authenticity and integrity (CIA) of the data that were sent in the request.

In practical deployment, Intermediate Server Application is responsible for building the normalized data for the purpose of computing the signature and passing it to PowerAuth 2.0 Server, since it knows details about the networking operation (for example, it knows what endpoint is being signed, what HTTP method it uses, etc.). PowerAuth 2.0 Server can then just simply accept any data and signature and perform signature validation - in ideal world, PowerAuth 2.0 Server should know nothing about the business domain it is used in.

## Computing the signature

PowerAuth 2.0 signature is in principle multi-factor - it uses all keys as defined in "PowerAuth Key Derivation" chapter. The signature may include one, two or three factors, therefore achieving 1FA, 2FA or 3FA. In order to determine the type of the signature, following constants are used:

- `possession` - Signature uses only possession related key KEY_SIGNATURE_POSSESSION.
- `knowledge` - Signature uses only knowledge related key KEY_SIGNATURE_KNOWLEDGE.
- `biometry` - Signature uses only biometry related key KEY_SIGNATURE_BIOMETRY.
- `possession_knowledge` - Signature uses two keys: a possession related key KEY_SIGNATURE_POSSESSION and then knowledge related key KEY_SIGNATURE_KNOWLEDGE.
- `possession_biometry` - Signature uses two keys: a possession related key KEY_SIGNATURE_POSSESSION and then biometry related key KEY_SIGNATURE_BIOMETRY.
- `possession_knowledge_biometry` - Signature uses three keys: a possession related key KEY_SIGNATURE_POSSESSION, then knowledge related key KEY_SIGNATURE_KNOWLEDGE, and finally biometry related key KEY_SIGNATURE_BIOMETRY.

When using more than one factor / key, the keys are added additively in the signature algorithm, so that the factors can be validated individually. The resulting PowerAuth 2.0 signature is a sequence of one to three numeric strings with 8 digits (each sequence is separated by "-" character) that is obtained in following manner:

```java
/**
 * Compute the signature for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param signatureKey - array of symmetric keys used for signature
 * @param CTR - counter
 */
public String computeSignature(byte[] data, Array<SecretKey> signatureKeys, int CTR) {

	// ... compute signature components
	String[] signatureComponents = new String[signatureKeys.count()];
	for (int i = 0; i < signatureKeys.count(); i++) {
		byte[] KEY_SIGNATURE = KeyConversion.secretKeyFromBytes(signatureKey.get(0));
		byte[] KEY_DERIVED = Mac.HMAC_SHA256(KEY_SIGNATURE, CTR);

		// ... compute signature key using more than one keys, at most 2 extra keys
		// ... this skips the key with index 0 when i == 0
		for (int j = 0; j < i; j++) {
			KEY_SIGNATURE = KeyConversion.secretKeyFromBytes(signatureKey.get(j + 1));
			KEY_DERIVED_CURRENT = Mac.HMAC_SHA256(KEY_SIGNATURE, CTR);
			KEY_DERIVED = Mac.HMAC_SHA256(KEY_DERIVED, KEY_DERIVED_CURRENT);
		}

		// ... sign the data
		byte[] SIGNATURE_LONG = Mac.HMAC_SHA256(DATA, KEY_DERIVED);

		// ... decimalize the signature component
		int signComponent = (TRUNCATE(SIGNATURE_LONG, 4) & 0x7FFFFFFF) % Math.pow(10,8);
		signatureComponents[i] = String.valueOf(signComponent);
	}

	// ... join the signature component using "-" character.
	return String.join("-", signatureComponents);
}
```

PowerAuth 2.0 Client sends the signature in the HTTP `X-PowerAuth-Authorization` header:

```http
X-PowerAuth-Authorization: PowerAuth
	pa_activationId="hbG9duZ19gyYaW5kb521fYWN0aXZhdGlvbl9JRaA",
	pa_applicationId="Z19gyYaW5kb521fYWN0aXZhdGlvbl9JRaAhbG9du",
	pa_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
	pa_signature_type="possession_knowledge_biometry"
	pa_signature="12345678-12345678-12345678",
	pa_version="2.0"
```
## Normalized data for HTTP requests

Normalized data to be signed are built using the following procedure:

```
DATA = ${REQUEST_METHOD}&${REQUEST_URI_IDENTIFIER_HASH}&${APPLICATION_SECRET}&${NONCE}&${REQUEST_DATA}
```

... where:

**//TODO: Design better way of normalizing request data and URI**

- `${REQUEST_METHOD}` - HTTP method written in upper-case, such as GET or POST.
- `${REQUEST_URI_IDENTIFIER_HASH}` - SHA256 hashed identifier of given URI of the resource (hexadecimal format), for example SHA256("/api/payment"). The hashed value (in the example before, the "/api/payment" stirng) should be uniquely chosen for each URI, but can be of an arbitrary format.
- `${APPLICATION_SECRET}` - An application secret key, used to bind an application identification in the signature explicitly.
- `${NONCE}` - Random 16 bytes encoded as Base64 using UTF-8 encoding, serving as a cryptographic nonce.
- `${REQUEST_DATA}` - Request data
	- In case of request without body (such as GET and DELETE requests), the request data is constructed from the URL query parameters (for example, GET request parameters) in a following way:
		1. Take all URL query parameters as key-value pairs:
			- `PARAM[i] = (KEY[i], VALUE[i]), i = 0 .. N`
		1. Sort all these key-value pairs according to `KEY[i]` first, then sort duplicate keys according to the `VALUE[i]`
		1. Construct data as concatenation of the sorted key-value pairs, key is separated from value using "=" character, individual key-value pairs are separated using "&" character:
			- `REQUEST_DATA = BASE64(CONCAT_ALL(CONCAT(KEY[j], VALUE[j], "="), "&", j = 0 .. N))` (let's assume that `j` are sorted indexes)
	- In case of request with body (such as POST and PUT requests), data from the resource body (bytes) are encoded using Base64 with UTF-8 encoding and appended:
		- `REQUEST_DATA = BASE64(HTTP['body'])`

## Validating the signature

PowerAuth 2.0 Server can validate the signature using the following mechanism:

1. Find the activation record using activation ID
1. Check the record state - if it is other than `ACTIVE`, terminate the validation.
1. Obtain `KEY_SERVER_PRIV` and `KEY_DEVICE_PUB` from the record.
1. Compute `KEY_MASTER_SECRET`.
	- `KEY_MASTER_SECRET = ECDH(KEY_SERVER_PRIV, KEY_DEVICE_PUB)`
1. Compute required signature keys (`KEY_SIGNATURE_POSSESSION`, `KEY_SIGNATURE_KNOWLEDGE` or `KEY_SIGNATURE_BIOMETRY`).
	- see "PowerAuth Key Derivation" section.
1. Compute the expected signature for obtained data and check if the expected signature matches the one sent with the client. Since the PowerAuth 2.0 Client may be ahead with counter from PowerAuth 2.0 Server, server should try couple extra indexes ahead:

```
		// input: CTR, TOLERANCE, data and signatureKeys
		boolean VERIFIED = false
		for (CRT_ITER = CTR; CTR_ITER++; CRT_ITER < CRT + TOLERANCE) {
			//... compute signature for given CTR_ITER, data and signature keys (see the algorithm above)
			String SIGNATURE = computeSignature(data, signatureKeys, CTR_ITER);
			if (SIGNATURE.equals(SIGNATURE_PROVIDED) && !VERIFIED) {
				VERIFIED = true
				CTR = CTR_ITER
			}
		}
		return VERIFIED;
```

Additionally, server may implement partial signature validation - basically evaluate each signature component separately. This may be used to determine if failed attempt counter should be decremented or not (since this allows distinguishing attacker who has a physical access to the PowerAuth 2.0 Client from attacker who randomly guesses signature).

# PowerAuth Standard API

In order to assure a standard behavior of various PowerAuth 2.0 implementations, fixed endpoint and request/response structure between PowerAuth 2.0 Client and Intermediate Server Application is specified for the key exchange algorithm.

While the PowerAuth 2.0 Client technically communicates with an Intermediate Server Application, all response data are actually built in PowerAuth 2.0 Server and Intermediate Server Application just forwards data back and forth. Therefore, we will further assume that the phrase "PowerAuth 2.0 Server responds to PowerAuth 2.0 Client" is a shortcut for "Intermediate Server Application requests a response from PowerAuth 2.0 Server and forwards the response to PowerAuth 2.0 Client".

Each PowerAuth 2.0 implementation that is located on a specific base URL then has `/pa/` prefixed endpoints by convention.

## Initiate activation

Application activation is a process of key exchange between a PowerAuth 2.0 Client and a PowerAuth 2.0 Server. During this process, an "activation record" is created on the PowerAuth 2.0 Server and related keys are stored on a PowerAuth 2.0 Client.

Exchange the public keys between PowerAuth 2.0 Client and PowerAuth 2.0 Server.

PowerAuth 2.0 Client sends a short activation ID, it's public key encrypted using activation OTP and a visual identification (or a "client name"):

- `id` - Represents an `ACTIVATION_ID_SHORT` value (first half of an activation code).
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `cDevicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC` AES encrypted with `ACTIVATION_OTP`
	- `cDevicePublicKey = AES(KEY_DEVICE_PUBLIC, activationNonce, ACTIVATION_OTP)`
- `clientName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".

PowerAuth 2.0 Server responds with an activation ID, public key encrypted using the activation OTP and device public key (for technical reasons, an ephemeral key is used here), and signature of this encrypted key created with the server's private master key:

- `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
- `ephemeralPublicKey` - A technical component for AES encryption - a public component of the on-the-fly generated key pair.
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `cServerPublicKey` - Encrypted public key `KEY_SERVER_PUBLIC` of the server.
	- `EPH_KEY = ECDH(ephemeralPrivateKey, KEY_DEVICE_PUBLIC)`
	- `cServerPublicKey = AES(AES(KEY_SERVER_PUBLIC, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`
- `cServerPublicKeySignature = ECDSA(cServerPublicKey, KEY_SERVER_MASTER_PRIVATE)`

After receiving the response, PowerAuth 2.0 Client verifies cSeverPublicKeySignature using server's public master key `KEY_SERVER_MASTER_PUBLIC` (optional) and decrypts server public key using it's private `ACTIVATION_OTP`.

- `signatureOK = ECDSA^inverse(cServerPublicKey, KEY_SERVER_MASTER_PUBLIC)`
- `EPH_KEY = ECDH(KEY_DEVICE_PRIVATE, ephemeralPublicKey)`
- `serverPublicKey = AES^inverse(AES^inverse(cServerPublicKey, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`

Then, PowerAuth 2.0 Client deduces `KEY_MASTER_SECRET`:

- `KEY_MASTER_SECRET = ECDH(KEY_DEVICE_PRIVATE, serverPublicKey)`

<table>
	<tr>
		<td>Method</td>
		<td>`POST`</td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td>`/pa/activation/create`</td>
	</tr>
</table>

### Request

- Headers:
	- Content-Type: application/json

```json
		{
			"requestObject": {
				"activationIdShort": "XDA57-24TBC",
				"activationNonce": "hbmRvbQRUNESF9QVUJMSUNfS0VZX3J==",
				"cDevicePublicKey": "RUNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
				"clientName": "My iPhone"
			}
		}
```

### Response

- Status Code: 200
- Headers:
	- Content-Type: application/json

```json
		{
			"status": "OK",
			"responseObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
				"activationNonce": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J==",
				"ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
				"cServerPublicKey": "NESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
				"cServerPublicKeySignature": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
			}
		}
```

## Activation status

Get the status of an activation with given activation ID. The PowerAuth 2.0 Server response contains an activation status blob that is AES encrypted with `KEY_TRANSPORT`.

- `cStatusBlob = AES(statusBlob, KEY_TRANSPORT)`

PowerAuth 2.0 Client can later trivially decrypt the original status blob:

- `statusBlob = AES^inverse(cStatusBlob, KEY_TRANSPORT)`

Structure of the status blob is following:

	0xDE 0xAD 0xBE 0xEF 1B:${STATUS} 4B:${CTR} 7B:${RANDOM_NOISE}

where:

- The first 4 bytes (0xDE 0xAD 0xBE 0xEF) are basically a fixed prefix.
- ${STATUS} - A status of the activation record, it can be one of following values:
	- 0x01 - CREATED
	- 0x02 - OTP_USED
	- 0x03 - ACTIVE
	- 0x04 - BLOCKED
	- 0x05 - REMOVED
- ${CTR} - 4 bytes representing information of the server counter (CTR value, as defined in PowerAuth 2.0 specification).
- ${RANDOM_NOISE} - Random 7 byte padding, a complement to the total length of 16B. These bytes also serve as a source of entropy for the transport (AES encrypted cStatusBlob will be different each time an endpoint is called).

<table>
	<tr>
		<td>Method</td>
		<td>`POST`</td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td>`/pa/activation/status`</td>
	</tr>
</table>

### Request

- Headers
	- Content-Type: application/json

```json
		{
			"requestObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f"
			}
		}
```

### Response

- Status code: 200
- Headers
	- Content-Type: application/json

```json
		{
			"status": "OK",
			"responseObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
				"cStatusBlob": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ=="
			}
		}
```

## Activation remove

Remove an activation with given ID, set it's status to REMOVED. Activation can be removed only after successful verification of the signature.

<table>
	<tr>
		<td>Method</td>
		<td>`POST`</td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td>`/pa/activation/remove`</td>
	</tr>
</table>

### Request

- Headers
	- Content-Type: application/json
	- X-PowerAuth-Authorization: PowerAuth ...

```json
			{
				"requestObject": {
					"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f"
				}
			}
```

#### Response

- Status code: 200
- Headers
	- Content-Type: application/json

```json
		{
			"status": "OK"
		}
```

# Implementation Details

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

Note: A single `ACTIVATION_OTP` must be valid only for a limited period of time (activation time window), that should be rather short (in minutes at most). Also, the activation OTP can be used only once - the moment client application sends and receives the encrypted public keys, it must be marked as "already used".

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
