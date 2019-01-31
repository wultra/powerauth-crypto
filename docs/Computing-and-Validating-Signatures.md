# Computing and Validating Signatures

While PowerAuth can be used for signing any type of data, the main objective of the protocol is to allow signing of HTTP requests sent to the server in order to prove consistency, authenticity and integrity (CIA) of the data that were sent in the request.

In practical deployment, Intermediate Server Application is responsible for building the normalized data for the purpose of computing the signature and passing it to PowerAuth Server, since it knows details about the networking operation (for example, it knows what endpoint is being signed, what HTTP method it uses, etc.). PowerAuth Server can then just simply accept any data and signature and perform signature validation - in ideal world, PowerAuth Server should know nothing about the business domain it is used in.

## Computing the Signature

PowerAuth signature is in principle multi-factor - it uses all keys as defined in "PowerAuth Key Derivation" chapter. The signature may include one, two or three factors, therefore achieving 1FA, 2FA or 3FA. In order to determine the type of the signature, following constants are used:

- **1FA** - only a single factor is used
	- `possession` - Signature uses only possession related key `KEY_SIGNATURE_POSSESSION`.
	- `knowledge` - Signature uses only knowledge related key `KEY_SIGNATURE_KNOWLEDGE`.
	- `biometry` - Signature uses only biometry related key `KEY_SIGNATURE_BIOMETRY`.
- **2FA** - possession and one another factor is used
	- `possession_knowledge` - Signature uses two keys: a possession related key `KEY_SIGNATURE_POSSESSION` and then knowledge related key `KEY_SIGNATURE_KNOWLEDGE`.
	- `possession_biometry` - Signature uses two keys: a possession related key `KEY_SIGNATURE_POSSESSION` and then biometry related key `KEY_SIGNATURE_BIOMETRY`.
- **3FA** - all three factors are used
	- `possession_knowledge_biometry` - Signature uses three keys: a possession related key `KEY_SIGNATURE_POSSESSION`, then knowledge related key `KEY_SIGNATURE_KNOWLEDGE`, and finally biometry related key `KEY_SIGNATURE_BIOMETRY`.

When using more than one factor / key, the keys are added additively in the signature algorithm, so that the factors can be validated individually. The resulting PowerAuth signature is a sequence of one to three numeric strings with 8 digits (each sequence is separated by "-" character) that is obtained in following manner:

```java
/**
 * Compute the signature for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param signatureKey - array of symmetric keys used for signature
 * @param CTR_DATA - hash based counter
 */
public String computeSignature(byte[] data, List<SecretKey> signatureKeys, byte[] CTR_DATA) {

	// ... compute signature components
	String[] signatureComponents = new String[signatureKeys.size()];
	for (int i = 0; i < signatureKeys.size(); i++) {
		byte[] KEY_SIGNATURE = KeyConversion.secretKeyFromBytes(signatureKey.get(0));
		byte[] KEY_DERIVED = Mac.hmacSha256(KEY_SIGNATURE, CTR_DATA);

		// ... compute signature key using more than one keys, at most 2 extra keys
		// ... this skips the key with index 0 when i == 0
		for (int j = 0; j < i; j++) {
			KEY_SIGNATURE = KeyConversion.secretKeyFromBytes(signatureKey.get(j + 1));
			KEY_DERIVED_CURRENT = Mac.hmacSha256(KEY_SIGNATURE, CTR_DATA);
			KEY_DERIVED = Mac.hmacSha256(KEY_DERIVED_CURRENT, KEY_DERIVED);
		}

		// ... sign the data
		byte[] SIGNATURE_LONG = Mac.hmacSha256(KEY_DERIVED, DATA);

		// ... decimalize the signature component
		int signComponent = (TRUNCATE(SIGNATURE_LONG, 4) & 0x7FFFFFFF) % Math.pow(10,8);
		signatureComponents[i] = String.valueOf(signComponent);
	}

	// ... join the signature component using "-" character.
	return String.join("-", signatureComponents);
}
```

PowerAuth Client sends the signature in the HTTP `X-PowerAuth-Authorization` header:

```
X-PowerAuth-Authorization: PowerAuth
	pa_activation_id="7a24c6e9-48e9-43c2-ab4a-aed6270e924d",
	pa_application_key="Z19gyYaW5kb521fYWN0aXZ==",
	pa_nonce="kYjzVBB8Y0ZFabxSWbWovY==",
	pa_signature_type="possession_knowledge_biometry"
	pa_signature="12345678-12345678-12345678",
	pa_version="3.0"
```
## Normalized Data for HTTP Requests

Normalized data to be signed are built using the following procedure:

```
REQUEST_DATA = ${REQUEST_METHOD}&${REQUEST_URI_IDENTIFIER}&${NONCE}&${REQUEST_BODY}
DATA = ${REQUEST_DATA}&${APPLICATION_SECRET}
```

_Note: Note that the `APPLICATION_SECRET` is technically outside the request data and is appended after the `REQUEST_DATA` normalization. This is because Intermediate Server Application does not know the `APPLICATION_SECRET` but must be able to forward normalized `REQUEST_DATA` to the PowerAuth Server._

... where:

- `${REQUEST_METHOD}` - HTTP method written in upper-case, such as GET or POST.
- `${REQUEST_URI_IDENTIFIER}` - identifier of given URI of the resource encoded as Base64 with UTF-8 encoding, for example `Base64.encode("/api/payment".getBytes("UTF-8"))`. The hashed value (in the example before, the "/api/payment" string) should be uniquely chosen for each URI, but can be of an arbitrary format (if not specified otherwise).
- `${APPLICATION_SECRET}` - An application secret key, used to bind an application identification in the signature explicitly. This value is 16B encoded as Base64 using UTF-8 encoding (see implementation notes).
- `${NONCE}` - Random 16 bytes (suggested length) encoded as Base64 using UTF-8 encoding, serving as a cryptographic nonce.
- `${REQUEST_BODY}` - Request body from the HTTP request
	- In case of request without body (such as GET and DELETE requests), the request data is constructed from the URL query parameters (for example, GET request parameters) in a following way:
		1. Take all URL query parameters as key-value pairs:
			- `PARAM[i] = (KEY[i], VALUE[i]), i = 0 .. N`
		1. Sort all these key-value pairs according to `KEY[i]` first, then sort duplicate keys according to the `VALUE[i]`
		1. Construct data as concatenation of the sorted key-value pairs, key is separated from value using "=" character, individual key-value pairs are separated using "&" character:
			- `REQUEST_DATA = BASE64.encode(CONCAT_ALL(CONCAT(KEY[j], VALUE[j], "="), "&", j = 0 .. N))` (let's assume that `j` are sorted indexes)
		1. _Note: The GET request normalization is inspired by the OAuth 1.0a request normalization._
	- In case of request with body (such as POST and PUT requests), data from the resource body (bytes) are encoded using Base64 with UTF-8 encoding and appended:
		- `REQUEST_DATA = BASE64.encode(ByteUtils.getBytes(HTTP['body']))`

## Validating the Signature

PowerAuth Server can validate the signature using the following mechanism:

1. Find the activation record using activation ID
1. Check the record state - if it is other than `ACTIVE`, terminate the validation.
1. Obtain `KEY_SERVER_PRIV` and `KEY_DEVICE_PUB` from the record.
1. Compute `KEY_MASTER_SECRET`.
	- `KEY_MASTER_SECRET = ECDH(KEY_SERVER_PRIV, KEY_DEVICE_PUB)`
1. Compute required signature keys (`KEY_SIGNATURE_POSSESSION`, `KEY_SIGNATURE_KNOWLEDGE` or `KEY_SIGNATURE_BIOMETRY`).
	- see "PowerAuth Key Derivation" section.
1. Compute the expected signature for obtained data and check if the expected signature matches the one sent with the client. Since the PowerAuth Client may be ahead with counter from PowerAuth Server, server should try couple extra indexes ahead:

```java
// input: CTR, CTR_DATA, TOLERANCE, data and signatureKeys
boolean VERIFIED = false
byte[] CTR_DATA_ITER = CTR_DATA
for (CRT_ITER = CTR; CTR_ITER++; CRT_ITER < CRT + TOLERANCE) {
    //... compute signature for given CTR_DATA_ITER, data and signature keys (see the algorithm above)
    String SIGNATURE = computeSignature(data, signatureKeys, CTR_DATA_ITER);
    if (SIGNATURE.equals(SIGNATURE_PROVIDED) && !VERIFIED) {
        VERIFIED = true
        CTR_DATA = CTR_DATA_ITER
        break
    }
    // Move to the next hash-based counter's value
    CTR_DATA_ITER = ByteUtils.convert32Bto16B(Hash.sha256(CTR_DATA_ITER))
}
return VERIFIED;
```

Additionally, server may implement partial signature validation - basically evaluate each signature component separately. This may be used to determine if a failed attempt counter should be incremented or not (since this allows distinguishing attacker who has a physical access to the PowerAuth Client from attacker who randomly guesses signature).
