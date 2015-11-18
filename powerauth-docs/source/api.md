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
