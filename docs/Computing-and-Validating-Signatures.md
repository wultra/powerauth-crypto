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

When using more than one factor / key, the keys are added additively in the signature algorithm, so that the factors can be validated individually. The resulting PowerAuth signature can be then represented in two different formats:

1. For online validation, PowerAuth signature is one Base64 string, which length depends on the number of factors involved in the calculation (16, 32 or 48 bytes encoded in Base64) 
1. For offline validation purposes, PowerAuth signature is a sequence of one to three numeric strings with 8 digits (each sequence is separated by “-“ character)

Both formats share the same core algorithm to calculate the signature components:

```java
/**
 * Compute the signature components for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param signatureKey - array of symmetric keys used for signature
 * @param CTR_DATA - hash based counter
 */
List<byte[]> computeSignatureComponents(byte[] data, List<SecretKey> signatureKeys, byte[] CTR_DATA) {
    // ... compute signature components
    List<byte[]> signatureComponents = new ArrayList<byte[]>();
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
        byte[] SIGNATURE_COMPONENT = Mac.hmacSha256(KEY_DERIVED, DATA);
        // ... keep it in the list
        signatureComponents.add(SIGNATURE_COMPONENT);
    }
    return signatureComponents;
}
```

### Signing HTTP requests

PowerAuth signature for online purposes can be obtained in following manner:

```java
/**
 * Compute the signature for HTTP request purposes for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param signatureKey - array of symmetric keys used for signature
 * @param CTR_DATA - hash based counter
 */
String computeOnlineSignature(byte[] data, List<SecretKey> signatureKeys, byte[] CTR_DATA) {
    // ... at first, calculate signature components
    List<byte[]> signatureBinaryComponents = computeSignatureComponents(data, signatureKeys, CTR_DATA);  
      
    // ... now convert components into one Base64 string
    byte[] signatureBytes = new byte[signatureKeys.size() * 16];
    for (int i = 0; i < signatureComponents.size(); i++) {
        byte[] SIGNATURE_COMPONENT = signatureBinaryComponents.get(i);
        // ... append last 16 bytes from SIGNATURE_COMPONENT to signature bytes        
        ByteUtils.copy(SIGNATURE_COMPONENT, 16, signatureBytes, i * 16, 16);
    }
    // ... final conversion to Base64
    return Base64.encode(signatureBytes);
}
```

PowerAuth Client sends the signature in the HTTP `X-PowerAuth-Authorization` header:

```
X-PowerAuth-Authorization: PowerAuth
	pa_activation_id="7a24c6e9-48e9-43c2-ab4a-aed6270e924d",
	pa_application_key="Z19gyYaW5kb521fYWN0aXZ==",
	pa_nonce="kYjzVBB8Y0ZFabxSWbWovY==",
	pa_signature_type="possession_knowledge"
	pa_signature="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	pa_version="3.1"
```

### Offline signature

Offline signatures are used in case when the mobile device is not connected to the internet. The computation of such signature is similar to signing HTTP requests, but the final string is more human readable and can be easily manually retyped: 

```java
/**
 * Compute the offline signature for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param signatureKey - array of symmetric keys used for signature
 * @param CTR_DATA - hash based counter
 */
String computeOfflineSignature(byte[] data, List<SecretKey> signatureKeys, byte[] CTR_DATA) {
    // ... at first, calculate signature components
    List<byte[]> signatureBinaryComponents = computeSignatureComponents(data, signatureKeys, CTR_DATA);
	
	// ... compute signature components
	String[] signatureComponents = new String[signatureKeys.size()];
    for (int i = 0; i < signatureComponents.size(); i++) {
        byte[] SIGNATURE_COMPONENT = signatureBinaryComponents.get(i);
        // ... decimalize the signature component
        int decimalized = (ByteUtils.getInt(ByteUtils.truncate(SIGNATURE_COMPONENT, 4)) & 0x7FFFFFFF) % Math.pow(10,8);
        signatureStrings[i] = String.valueOf(decimalized);
	}
    // ... join the signature component using "-" character.
    return String.join("-", signatureComponents);
}
```

PowerAuth Client displays the signature on the screen and then the user has to manually retype that string into another PowerAuth powered application (e.g. typically to web application, connected to PowerAuth Server). You can read more about the offline signatures in PowerAuth Server's [Offline Signatures](https://github.com/wultra/powerauth-server/blob/develop/docs/Offline-Signatures.md) documentation.

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

In case the data for offline signature is being normalized, then the following rules are applied:

- `${REQUEST_METHOD}` is always set to `POST`.
- `${APPLICATION_SECRET}` is always set to the string constant `offline`.

## Validating the Signature

### Constants and variables

Following constants and variables are involved in the signature validation:

- `CTR`, signature counter
  - Is a representation of logical time. Each parts in the scheme (client and server) increments the counter independently.
  - In protocol version `2`, the counter was involved in the signature calculation.
  - In protocol version `3`, the counter has only informational value and is no longer involved in the signature calculation.
- `CTR_DATA`, hash based signature counter
  - Introduced in the protocol version `3`, now is involved in the signature calculation.
  - It's randomly initialized and exchanged during the activation, or in the protocol upgrade process.
  - In protocol version `3.1`, the client can synchronize its counter with the server. 
- `CTR_LOOK_AHEAD`, tolerance set on server to overcome ahead clients
  - Server is trying to calculate and validate the signature ahead in time, in half-closed interval defined by this tolerance: `[CTR, CTR + CTR_LOOK_AHEAD)`.
  - Default value is `20`
- `FAILED_ATTEMPTS`, how many attempts failed before in row
   - Initial value is `0`.
   - If value reaches value defined in `MAX_FAILED_ATTEMPTS`, then activation is set to `BLOCKED` state.
   - Value is increased in case that signature validation fails (see description below)
- `MAX_FAILED_ATTEMPTS`, how many maximum failed attempts in a row result in blocked activation. 
   - If `FAILED_ATTEMPTS` reaches this value, then activation is set to `BLOCKED` state.


### Algorithm

PowerAuth Server can validate the signature using the following mechanism:

1. Find the activation record using activation ID
1. Check the record state - if it is other than `ACTIVE`, terminate the validation.
1. Obtain `KEY_SERVER_PRIV` and `KEY_DEVICE_PUB` from the record.
1. Compute `KEY_MASTER_SECRET`.
	- `KEY_MASTER_SECRET = ByteUtils.convert32Bto16B(ECDH.phase(KEY_SERVER_PRIV, KEY_DEVICE_PUB))`
1. Compute required signature keys (`KEY_SIGNATURE_POSSESSION`, `KEY_SIGNATURE_KNOWLEDGE` or `KEY_SIGNATURE_BIOMETRY`).
	- see "PowerAuth Key Derivation" section.
1. Compute the expected signature for obtained data and check if the expected signature matches the one sent with the client. Since the PowerAuth Client may be ahead with counter from PowerAuth Server, server should try couple extra indexes ahead:

```java
// input: CTR, CTR_DATA, CTR_LOOK_AHEAD, data and signatureKeys
boolean VERIFIED = false
byte[] CTR_DATA_ITER = CTR_DATA
for (CTR_ITER = CTR; CTR_ITER++; CTR_ITER < CRT + CTR_LOOK_AHEAD) {
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

#### Success

In case that signature is successfully verified, then:

- Set `FAILED_ATTEMPTS` to `0`, but only if the signature factor is not `possession`. 
- In case that signature with `possession` factor only is validated, then do not reset `FAILED_ATTEMPTS`.
- Move signature counter in database forward. That means that set `CTR` to `CTR_ITER` and `CTR_DATA` to `CTR_DATA_ITER`.

#### Failure

In case of failure:

- Increase `FAILED_ATTEMPTS` by `1`, but only if the signature factor is not `possession`.
- In case that signature with `possession` factory only is validated, then do not increase `FAILED_ATTEMPTS`.
- If `FAILED_ATTEMPTS` is equal or greater than `MAX_FAILED_ATTEMPTS`, then set activation state to `BLOCKED`.
