# PowerAuth 2.0 Standard RESTful API

In order to assure a standard behavior of various PowerAuth 2.0 implementations, fixed endpoint and request/response structure between PowerAuth 2.0 Client and Intermediate Server Application is specified for the key exchange algorithm.

While the PowerAuth 2.0 Client technically communicates with an Intermediate Server Application, all response data are actually built in PowerAuth 2.0 Server and Intermediate Server Application just forwards data back and forth. Therefore, we will further assume that the phrase "PowerAuth 2.0 Server responds to PowerAuth 2.0 Client" is a shortcut for "Intermediate Server Application requests a response from PowerAuth 2.0 Server and forwards the response to PowerAuth 2.0 Client".

Each PowerAuth 2.0 implementation that is located on a specific base URL then has `/pa/` prefixed endpoints by convention.

Following endpoints are published in PowerAuth 2.0 Standard RESTful API:

- [`/pa/activation/create`](#initiate-activation) - Create a new activation, perform a key exchange based on short activation ID.
- [`/pa/activation/status`](#activation-status) - Query for an activation status.
- [`/pa/activation/remove`](#activation-remove) - Remove an activation (requires authentication).
- [`/pa/vault/unlock`](#vault-unlock) - Get a key to unlock secure vault (requires authentication).

## Initiate activation

Exchange the public keys between PowerAuth 2.0 Client and PowerAuth 2.0 Server.

Application activation is a process of key exchange between a PowerAuth 2.0 Client and a PowerAuth 2.0 Server. During this process, an "activation record" is created on the PowerAuth 2.0 Server and related keys are stored on a PowerAuth 2.0 Client.

PowerAuth 2.0 Client sends following data on the server:

- `activationIdShort` - Represents an `ACTIVATION_ID_SHORT` value (first half of an activation code).
- `applicationKey` - Represents an application with a given `APPLICATION_KEY` which should be entitled to complete the activation.
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `activationName` - Visual representation of the device, for example "Johnny's iPhone" or "Samsung Galaxy S".
- `applicationSignature` - Signature using an application secret, to prove that the activation was completed using a given application.
	- `SecretKey signatureKey = KeyConversion.secretKeyFromBytes(Base64.decode(APPLICATION_SECRET))`
	- `byte[] applicationSignature = Mac.hmacSha256(signatureKey, id + "&" + Base64.encode(activationNonce) + "&" + Base64.encode(encryptedDevicePublicKey) + "&" + applicationKey)`
- `encryptedDevicePublicKey` - Represents a public key `KEY_DEVICE_PUBLIC` AES encrypted with `ACTIVATION_OTP`.
	- `byte[] encryptedDevicePublicKey = AES.encrypt(KEY_DEVICE_PUBLIC, activationNonce, ACTIVATION_OTP)`
- `extras` - Any client side attributes associated with this activation, like a more detailed information about the client, etc.

PowerAuth 2.0 Server verifies the `applicationSignature` and if it matches the expected value, it responds with an following data:

- `activationId` - Represents a long `ACTIVATION_ID` that uniquely identifies given activation records.
- `activationNonce` - Represents an activation nonce, used as an IV for AES encryption.
- `ephemeralPublicKey` - A technical component for AES encryption - a public component of the on-the-fly generated key pair.
- `encryptedServerPublicKey` - Encrypted public key `KEY_SERVER_PUBLIC` of the server.
	- `SharedKey EPH_KEY = ECDH.phase(ephemeralPrivateKey, KEY_DEVICE_PUBLIC)`
	- `byte[] encryptedServerPublicKey = AES.encrypt(AES.encrypt(KEY_SERVER_PUBLIC, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`
- `serverDataSignature` - Signature of the server data - concatenated `activationId` bytes and `encryptedServerPublicKey`.
	- `byte[] activationData = ByteUtils.concat(activationId.getBytes("UTF-8"), encryptedServerPublicKey)`
	- `byte[] serverDataSignature = ECDSA.sign(activationData, KEY_SERVER_MASTER_PRIVATE)`

After receiving the response, PowerAuth 2.0 Client verifies `severDataSignature` using server's public master key `KEY_SERVER_MASTER_PUBLIC` and if the signature is OK, it decrypts server public key using it's private master key `KEY_DEVICE_PRIVATE` and `ACTIVATION_OTP`.

- `byte[] activationData = ByteUtils.concat(activationId.getBytes("UTF-8"), encryptedServerPublicKey)`
- `signatureOK = ECDSA.verify(activationData, serverDataSignature, KEY_SERVER_MASTER_PUBLIC)`
- `EPH_KEY = ECDH.phase(KEY_DEVICE_PRIVATE, ephemeralPublicKey)`
- `serverPublicKey = AES.decrypt(AES.decrypt(encryptedServerPublicKey, activationNonce, ACTIVATION_OTP), activationNonce, EPH_KEY)`

Then, PowerAuth 2.0 Client deduces `KEY_MASTER_SECRET`:

- `KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE, serverPublicKey)`

After that, it proceeds with key derivation. See a separate chapter "PowerAuth Key Derivation" for details.

<table>
	<tr>
		<td>Method</td>
		<td><code>POST</code></td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td><code>/pa/activation/create</code></td>
	</tr>
</table>

### Request

- Headers:
	- `Content-Type: application/json`

```json
		{
			"requestObject": {
				"activationIdShort": "XDA57-24TBC",
				"applicationKey": "UNfS0VZX3JhbmRvbQ==",
				"activationNonce": "hbmRvbQRUNESF9QVUJMSUNfS0VZX3J==",
				"activationName": "My iPhone",
				"applicationSignature": "SF9QRUNEVUJMSUNfS0VZX3JhbmRvbQ==",
				"encryptedDevicePublicKey": "RUNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
				"extras": "Any data in any format (XML, JSON, ...) for application specific purposes"
			}
		}
```

### Response

- Status Code: `200`
- Headers:
	- `Content-Type: application/json`

```json
		{
			"status": "OK",
			"responseObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
				"activationNonce": "vbQRUNESF9hbmRQVUJMSUNfS0VZX3J==",
				"ephemeralPublicKey": "MSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJ==",
				"encryptedServerPublicKey": "NESF9QVUJMSUNfS0VZX3JhbmRvbQNESF9QVUJMSUNfS0VZX3JhbmRvbQ==",
				"serverDataSignature": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
			}
		}
```

## Activation status

Get the status of an activation with given activation ID. The PowerAuth 2.0 Server response contains an activation status blob that is AES encrypted with `KEY_TRANSPORT`.

- `encryptedStatusBlob = AES.encrypt(statusBlob, ByteUtils.zeroBytes(32), KEY_TRANSPORT, "AES/CBC/NoPadding")`

PowerAuth 2.0 Client can later trivially decrypt the original status blob:

- `statusBlob = AES.decrypt(encryptedStatusBlob, ByteUtils.zeroBytes(32), KEY_TRANSPORT, "AES/CBC/NoPadding")`

Structure of the 32B long status blob is following:

```java
	0xDE 0xAD 0xBE 0xEF 1B:${STATUS} 8B:${CTR} 1B:${FAIL_COUNT} 1B:${MAX_FAIL_COUNT} 17B:${RANDOM_NOISE}
```

where:

- The first 4 bytes (`0xDE 0xC0 0xDE 0xD1`) are basically a fixed prefix.
- `${STATUS}` - A status of the activation record, it can be one of following values:
	- `0x01 - CREATED`
	- `0x02 - OTP_USED`
	- `0x03 - ACTIVE`
	- `0x04 - BLOCKED`
	- `0x05 - REMOVED`
- `${CTR}` - 8 bytes representing information of the server counter (`CTR` value, as defined in PowerAuth 2.0 specification).
- `${FAIL_COUNT}` - 1 byte representing information about the number of failed attempts at the moment.
- `${MAX_FAIL_COUNT}` - 1 byte representing information about the maximum allowed number of failed attempts.
- `${RANDOM_NOISE}` - Random 17 byte padding (a complement to the total length of 32B). These bytes also serve as a source of entropy for the transport (AES encrypted `cStatusBlob` will be different each time an endpoint is called).

<table>
	<tr>
		<td>Method</td>
		<td><code>POST</code></td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td><code>/pa/activation/status</code></td>
	</tr>
</table>

### Request

- Headers
	- `Content-Type: application/json`

```json
		{
			"requestObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f"
			}
		}
```

### Response

- Status code: `200`
- Headers
	- `Content-Type: application/json`

```json
		{
			"status": "OK",
			"responseObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
				"encryptedStatusBlob": "19gyYaW5ZhdGlvblkb521fYWN0aX9JRaAhbG9duZ=="
			}
		}
```

## Activation remove

Remove an activation with given ID, set it's status to REMOVED. Activation can be removed only after successful verification of the signature.

PowerAuth 2.0 Client sends an authenticated request using an activation ID - authentication is carried around using the standard PowerAuth 2.0 signature with at least 2 factors (2FA).

In order to construct the PowerAuth 2.0 Client signature, use `/pa/activation/remove` as URI identifier part of the signature data.

<table>
	<tr>
		<td>Method</td>
		<td><code>POST</code></td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td><code>/pa/activation/remove</code></td>
	</tr>
</table>

### Request

- Headers
	- `Content-Type: application/json`
	- `X-PowerAuth-Authorization: PowerAuth ...`
- Body: empty

#### Response

- Status code: `200`
- Headers
	- `Content-Type: application/json`

```json
		{
			"status": "OK"
		}
```

## Vault unlock

Get the vault unlock key in order to decrypt data stored in the vault, for example the original `KEY_DEVICE_PRIVATE`.

PowerAuth 2.0 Client sends an authenticated request using an activation ID - authentication is carried around using the standard PowerAuth 2.0 signature with at least 2 factors (2FA).

In response, PowerAuth 2.0 Server sends a `KEY_ENCRYPTION_VAULT` key encrypted using `KEY_ENCRYPTION_VAULT_TRANSPORT` key associated with given counter (derived from the `KEY_TRANSPORT` master key, see the `PowerAuth Key Derivation` chapter for details).

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT_TRANSPORT)`

PowerAuth 2.0 Client can later decrypt the key using the inverse mechanism:

- `encryptedVaultEncryptionKey = AES.encrypt(KeyConversion.getBytes(KEY_ENCRYPTION_VAULT), ByteUtils.zeroBytes(16), KEY_ENCRYPTION_VAULT_TRANSPORT)`

_Note: Both the signature calculation / validation and `KEY_ENCRYPTION_VAULT_TRANSPORT` key derivation should increase the counter `CTR`! In other words, if signature uses value of `CTR = N`, key derivation should use `CTR = N + 1`. For technical reason, the client should compute the `KEY_ENCRYPTION_VAULT_TRANSPORT` ahead - we need to assure that only server may be behind the client with a `CTR` value, not vice versa._

<table>
	<tr>
		<td>Method</td>
		<td><code>POST</code></td>
	</tr>
	<tr>
		<td>Resource URI</td>
		<td><code>/pa/vault/unlock</code></td>
	</tr>
</table>

### Request

- Headers:
	- `Content-Type: application/json`
	- `X-PowerAuth-Authorization: PowerAuth ...`

### Response

- Status Code: `200`
- Headers:
	- `Content-Type: application/json`

```json
		{
			"status": "OK",
			"responseObject": {
				"activationId": "c564e700-7e86-4a87-b6c8-a5a0cc89683f",
				"encryptedVaultEncryptionKey": "QNESF9QVUJMSUNfS0VZX3JhbmRvbQ=="
			}
		}
```
