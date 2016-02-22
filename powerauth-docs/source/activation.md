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

The sequence diagrams below explain the PowerAuth 2.0 key exchange. It shows how PowerAuth 2.0 Client, Intermediate Server Application, Master Front-End Application and PowerAuth 2.0 Server play together in order to establish a shared secret between the client application and PowerAuth Server.

For the sake of the simplicity, we have split the process into three diagrams. The details of individual steps can be found in the chapter below ("Activation Flow - Description").

### Activation Initialization

This diagram shows how Master Front-End Application requests the activation data from the PowerAuth 2.0 Server. The process is initiated by the Master Front-End Application (for example, the Internet banking in the web browser) and it also ends here: by displaying the activation data so that they can be entered in the PowerAuth 2.0 Client.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-activation-init.png" width="100%"/>

### Key Exchange

This diagram shows how public keys are exchanged between PowerAuth 2.0 Client and PowerAuth 2.0 Server, and how  master shared secret and PowerAuth Standard Keys are derived. The Master Front-End Application plays no active role in the process of a key exchange.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-activation-prepare.png" width="100%"/>

### Activation Commit

Finally, the last diagram shows how Master Front-End Application proactively checks the status of the activation and allows it's completion by committing the activation record. A PowerAuth 2.0 Client plays a very little role in this step - it only shows a public key fingerprint so that the key exchange can be confirmed before committing the activation.

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/powerauth-activation-commit.png" width="100%"/>

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
	- `boolean isOK = ECDSA.verify(DATA, ACTIVATION_SIGNATURE, KEY_SERVER_MASTER_PUBLIC)`

1. PowerAuth 2.0 Client generates its key pair `(KEY_DEVICE_PRIVATE, KEY_DEVICE_PUBLIC)`.

	- `KeyPair keyPair = KeyGenerator.randomKeyPair()`
	- `PrivateKey KEY_DEVICE_PRIVATE = keyPair.getPrivate()`
	- `PublicKey KEY_DEVICE_PUBLIC = keyPair.getPublic()`

1. PowerAuth 2.0 Client sends a request with an `ACTIVATION_ID_SHORT`, `ACTIVATION_NONCE` (used as an initialization vector for AES encryption) and `C_KEY_DEVICE_PUBLIC` to the PowerAuth 2.0 Server (via Intermediate Server Application). Request also contains an application signature `APPLICATION_SIGNATURE` computed using `APPLICATION_SECRET` and activation data.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `byte[] ACTIVATION_NONCE = Generator.randomBytes(16)`
	- `byte[] keyPublicBytes = KeyConversion.getBytes(KEY_DEVICE_PUBLIC)`
	- `byte[] C_KEY_DEVICE_PUBLIC = AES.encrypt(keyPublicBytes, ACTIVATION_NONCE, KEY_ENCRYPTION_OTP)`
	- `SecretKey signingKey = KeyConversion.secretKeyFromBytes(Base64.decode(APPLICATION_SECRET))`
	- `byte[] APPLICATION_SIGNATURE = Mac.hmacSha256(signingKey, ACTIVATION_ID_SHORT + "&" + ACTIVATION_NONCE + "&" + C_KEY_DEVICE_PUBLIC + "&" + APPLICATION_KEY)`

1. PowerAuth 2.0 Server verifies that the application signature matches expected application and if it does, it decrypts and stores the public key at given record (otherwise, the server returns a generic error).

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `byte[] keyPublicBytes = AES.decrypt(C_KEY_DEVICE_PUBLIC, ACTIVATION_NONCE, KEY_ENCRYPTION_OTP)`
	- `PublicKey KEY_DEVICE_PUBLIC = KeyConversion.publicKeyFromBytes(keyPublicBytes)`

1. PowerAuth 2.0 Server changes the record status to `OTP_USED`.

1. PowerAuth 2.0 Server responds with `ACTIVATION_ID`, `C_KEY_SERVER_PUBLIC`, `KEY_EPHEMERAL_PUBLIC` and `SERVER_DATA_SIGNATURE`.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `KeyPair keyPair = KeyGenerator.randomKeyPair()`
	- `PrivateKey KEY_EPHEMERAL_PRIVATE = keyPair.getPrivate()`
	- `PublicKey KEY_EPHEMERAL_PUBLIC = keyPair.getPublic()`
	- `SecretKey EPH_KEY = ECDH.phase(KEY_EPHEMERAL_PRIVATE, KEY_DEVICE_PUBLIC)`
	- `byte[] EPHEMERAL_NONCE = Generator.randomBytes(16)`
	- `byte[] keyPublicBytes = KeyConversion.getBytes(KEY_SERVER_PUBLIC)`
	- `byte[] C_KEY_SERVER_PUBLIC = AES.encrypt(AES.encrypt(keyPublicBytes, EPHEMERAL_NONCE, KEY_ENCRYPTION_OTP), EPHEMERAL_NONCE, EPH_KEY)`
	- `byte[] activationIdBytes = ACTIVATION_ID.getBytes("UTF-8")`
	- `byte[] activationData = ByteUtils.concat(C_KEY_SERVER_PUBLIC, activationIdBytes)`
	- `byte[] SERVER_DATA_SIGNATURE = ECDSA.sign(activationData, KEY_SERVER_MASTER_PRIVATE)`

1. PowerAuth 2.0 Client receives an `ACTIVATION_ID`, `C_KEY_SERVER_PUBLIC`, `KEY_EPHEMERAL_PUBLIC` and `SERVER_DATA_SIGNATURE` and if the signature matches the data, it retrieves `KEY_SERVER_PUBLIC`.

	- `SecretKey KEY_ENCRYPTION_OTP = PBKDF2.expand(ACTIVATION_OTP, ACTIVATION_ID_SHORT.getBytes("UTF-8"), 10 000)`
	- `byte[] activationIdBytes = ACTIVATION_ID.getBytes("UTF-8")`
	- `byte[] activationData = ByteUtils.concat(C_KEY_SERVER_PUBLIC, activationIdBytes)`
	- `boolean isSignatureOK = ECDSA.verify(activationData, SERVER_DATA_SIGNATURE, KEY_SERVER_MASTER_PUBLIC)`
	- `SecretKey EPH_KEY = ECDH.phase(KEY_DEVICE_PRIVATE, KEY_EPHEMERAL_PUBLIC)`
	- `byte[] keyPublicBytes = AES.decrypt(AES.decrypt(C_KEY_SERVER_PUBLIC, EPHEMERAL_NONCE, EPH_KEY), EPHEMERAL_NONCE, KEY_ENCRYPTION_OTP)`
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

After completing the activation, client must store derived keys and throw away unencrypted device private key and key master secret. Only the derived keys should be stored on the device according to the description in "PowerAuth Key Derivation" chapter.
