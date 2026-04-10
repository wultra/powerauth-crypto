# Computing and Validating Authentication Codes

While PowerAuth can be used for authentication of any type of data, the main objective of the protocol is to allow authenticating HTTP requests sent to the server in order to prove consistency, authenticity and integrity (CIA) of the data that were sent in the request.

In practical deployment, Intermediate Server Application is responsible for building the normalized data for the purpose of computing the authentication code and passing it to PowerAuth Server, since it knows details about the networking operation (for example, it knows what endpoint is being signed, what HTTP method it uses, etc.). PowerAuth Server can then just simply accept any data and authentication code and perform authentication code validation. In an ideal world, PowerAuth Server should know nothing about the business domain it is used in.

> Note that **"PowerAuth Authentication Code"** is a new terminology for former term **"PowerAuth Signature"**.

## Normalized Data for HTTP Requests

Normalized data to be signed are built using the following procedure:

```
REQUEST_DATA = ${REQUEST_METHOD}&${REQUEST_URI_IDENTIFIER}&${NONCE}&${REQUEST_BODY}
DATA = ${REQUEST_DATA}&${APPLICATION_SECRET}
```

<!-- begin box info -->
Note that the `APPLICATION_SECRET` is technically outside the request data and is appended after the `REQUEST_DATA` normalization. This is because Intermediate Server Application does not know the `APPLICATION_SECRET` but must be able to forward normalized `REQUEST_DATA` to the PowerAuth Server.
<!-- end -->

The components of the string above are the following:

- `${REQUEST_METHOD}` - HTTP method written in upper-case, such as GET or POST.
- `${REQUEST_URI_IDENTIFIER}` - identifier of given URI of the resource encoded as Base64 with UTF-8 encoding, for example `Base64.encode("/api/payment".getBytes("UTF-8"))`. The hashed value (in the example before, the `/api/payment` string) should be uniquely chosen for each URI, but can be of an arbitrary format (if not specified otherwise).
- `${APPLICATION_SECRET}` - An application secret key, used to bind an application identification in the authentication explicitly. This value is 16B encoded as Base64 using UTF-8 encoding (see implementation notes).
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

In case the data for offline authentication is being normalized, then the following rules are applied:

- `${REQUEST_METHOD}` is always set to `POST`.
- `${APPLICATION_SECRET}` is always set to the string constant `offline`.

## Factor keys

All authentication code factor keys are initially derived from `KDK_AUTHENTICATION_CODE` - an intermediate key derivation key.

### Possession factor

```java
SecretKey KDK_AUTHENTICATION_CODE = KDF.derive(KEY_ACTIVATION_SECRET, "auth");
SecretKey KEY_AUTHENTICATION_CODE_POSSESSION = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/possession");
```

### Knowledge factor

```java
SecretKey KDK_AUTHENTICATION_CODE = KDF.derive(KEY_ACTIVATION_SECRET, "auth");
SecretKey KEY_AUTHENTICATION_CODE_KNOWLEDGE = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/knowledge");
```

The knowledge factor password (PIN) can be changed using the [dynamic factor keys](./Dynamic-Factor-Keys.md) functionality.

### Biometry factor

```java
SecretKey KDK_AUTHENTICATION_CODE = KDF.derive(KEY_ACTIVATION_SECRET, "auth");
SecretKey KEY_AUTHENTICATION_CODE_BIOMETRY = KDF.derive(KDK_AUTHENTICATION_CODE, "auth/biometry");
```

The biometry factor can be added or removed using the [dynamic factor keys](./Dynamic-Factor-Keys.md) functionality.

## Computing the authentication code

PowerAuth authentication code is in principle multifactor. It uses factor keys as derived above. The authentication code may include one or two factors, therefore achieving 1FA or 2FA. In order to determine the type of the authentication code, following constants are used:

- **1FA** - only a single factor is used
	- `possession` - Authentication code uses only possession related key `KEY_AUTHENTICATION_CODE_POSSESSION`.
- **2FA** - possession and one another factor is used
	- `possession_knowledge` - Authentication code uses two keys: a possession related key `KEY_AUTHENTICATION_CODE_POSSESSION` and then knowledge related key `KEY_AUTHENTICATION_CODE_KNOWLEDGE`.
	- `possession_biometry` - Authentication code uses two keys: a possession related key `KEY_AUTHENTICATION_CODE_POSSESSION` and then biometry related key `KEY_AUTHENTICATION_CODE_BIOMETRY`.

When using more than one factor key, the keys are added additively in the authentication algorithm, so that the factors can be validated individually. The resulting PowerAuth authentication code can be then represented in two different formats:

1. For online validation, the PowerAuth authentication code is one Base64 string. The length depends on the number of factors involved in the calculation (32, 64 or 96 bytes encoded in Base64).
1. For offline validation purposes, the PowerAuth authentication code is a sequence of one to three numeric strings with configurable amount of digits, each sequence is separated by "-" character.

Both formats share the same core algorithm to calculate the authentication code components:

```java
/**
 * Compute the authentication code components for given data using provided factor keys and current counter.
 * @param data - data to be signed
 * @param factorKeys - array of symmetric keys used for authentication code
 * @param CTR_DATA - hash based counter
 */
List<byte[]> computeAuthenticationCodeComponents(byte[] data, List<SecretKey> factorKeys, byte[] CTR_DATA) {
    // ... compute authentication code components
    String LABEL = "PA4CODE";
    List<byte[]> authCodeComponents = new ArrayList<byte[]>();
    for (int i = 1; i <= factorKeys.size(); i++) {
        byte[] KEY_DERIVED_BYTES = null;
        for (int j = 1; j <= i; j++) {
            byte[] INTERMEDIATE_DATA = ByteUtils.concat(CTR_DATA, KEY_DERIVED_BYTES);
            KEY_DERIVED_BYTES = Mac.kmac256(factorKeys.get(j - 1), INTERMEDIATE_DATA, 32, LABEL);
        }
        // ... compute MAC
        SecretKey KEY_DERIVED = KeyConversion.secretKeyFromBytes(KEY_DERIVED_BYTES);
        byte[] AUTH_CODE_COMPONENT = Mac.kmac256(KEY_DERIVED, data, 32, LABEL);
        // ... keep it in the list
        authCodeComponents.add(AUTH_CODE_COMPONENT);
    }
    return authCodeComponents;
}
```

### Authenticating HTTP Requests

PowerAuth authentication code for online purposes can be obtained in the following manner:

```java
/**
 * Compute the authentication code for HTTP request purposes for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param factorKeys - array of symmetric keys used for authentication code
 * @param CTR_DATA - hash based counter
 */
String computeOnlineAuthenticationCode(byte[] data, List<SecretKey> factorKeys, byte[] CTR_DATA) {
    // ... at first, calculate authentication code components
    List<byte[]> authCodeBinaryComponents = computeAuthenticationCodeComponents(data, factorKeys, CTR_DATA);  

    // ... now convert components into one Base64 string
    byte[] authCodeBytes = new byte[factorKeys.size() * 32];
    for (int i = 0; i < authCodeBinaryComponents.size(); i++) {
        byte[] AUTH_CODE_COMPONENT = authCodeBinaryComponents.get(i);
        // ... append component bytes to final authentication code bytes
        ByteUtils.copy(AUTH_CODE_COMPONENT, 0, authCodeBytes, i * 32, 32);
    }
    // ... final conversion to Base64
    return Base64.encode(authCodeBytes);
}
```

PowerAuth Client sends the authentication code value in the HTTP `X-PowerAuth-Authorization` header:

```
X-PowerAuth-Authorization: PowerAuth
 	pa_activation_id="3b09d6fd-9640-4731-bc99-8324672f4b27",
 	pa_application_key="oQ9jp0rJ+8zpJcBwaHCv6g==", 
 	pa_nonce="nHLMxrOzq0JxANqYPDO5xQ==", 
 	pa_auth_code_type="possession_knowledge", 
 	pa_auth_code="Hxdu5EYzKG1R2EvifAr45cFkYHTbaxuhFhUNh6yOa6OcPhP8Pp8iSszlAKQPW8w6sIAFYbQAsvxjK/VKs1elqw==", 
 	pa_version="4.0" 
```

### Offline authentication code

Offline authentication codes are used in case when the mobile device is not connected to the internet. The computation of such authentication code is similar to authenticating HTTP requests, but the final string is more human readable and can be easily manually retyped. Also, some of the attributes that would otherwise be present in the HTTP header need to have static value:

| Parameter                | Value                                        |
|--------------------------|----------------------------------------------|
| `REQUEST_METHOD`         | `POST` (recommended)                         |
| `REQUEST_URI_IDENTIFIER` | `/operation/authorize/offline` (recommended) |
| `APPLICATION_KEY`        | _not used_                                   |
| `APPLICATION_SECRET`     | `offline`                                    |

The following algorithm produces a short decimal authentication code value:

```java
/**
 * Compute the offline authentication code for given data using provided keys and current counter.
 * @param data - data to be signed
 * @param factorKeys - array of symmetric keys used for authentication code
 * @param CTR_DATA - hash based counter
 * @param componentLength - Length of authentication code component. Value should not be less than 4 or greater than 8.
 */
String computeOfflineAuthenticationCode(byte[] data, List<SecretKey> factorKeys, byte[] CTR_DATA, int componentLength) {
    // Validate length of authentication code component
    if (componentLength < 4 || componentLength > 8) {
        throw new IllegalArgumentException("componentLength is out of allowed range");
    }
    // calculate authentication code components
    List<byte[]> authCodeBinaryComponents = computeAuthenticationCodeComponents(data, factorKeys, CTR_DATA);
	
    // ... compute authentication code components
	String[] authCodeComponents = new String[factorKeys.size()];
    for (int i = 0; i < authCodeComponents.size(); i++) {
        byte[] AUTH_CODE_COMPONENT = authCodeBinaryComponents.get(i);
        // ... decimalize the authentication code component
        int decimalized = (ByteUtils.getInt(ByteUtils.truncate(AUTH_CODE_COMPONENT, 4)) & 0x7FFFFFFF) % Math.pow(10,8);
        authCodeComponents[i] = String.format("%0" + componentLength + "d", decimalized);
	}
    // ... join the decimalized components using "-" character.
    return String.join("-", authCodeComponents);
}
```

### Hash-based Counter

The `CTR_DATA` is a hash-based counter used to guarantee freshness of authentication codes and to prevent replay attacks. It is initialized with a random value during activation (or protocol upgrade) and then advanced deterministically after each operation. Unlike the numeric counter, `CTR_DATA` is updated using a one-way cryptographic function, so the next value cannot be predicted backwards and does not leak information about the number of requests. The next counter value is computed using:

```java
byte[] CTR_DATA_next = Hash.sha3_256(CTR_DATA);
```

### Loop Unrolling

The following examples explain how multi-factor authentication code components are derived from factor keys in the protocol. The core idea is that each additional factor extends a KMAC-based derivation chain, where `CTR_DATA` is always part of the input and `||` denotes byte concatenation. For 1F, the derived key is computed directly from `CTR_DATA` using factor 0 and then used to compute the MAC over request data. For 2F and 3F, the derivation becomes nested, so that factor 1 depends on the result of factor 0, and factor 2 depends on the result of factor 1 (which already includes factor 0). This chaining binds factors together in a deterministic order and ensures that the resulting authentication code cannot be computed or validated correctly unless all required factors are available.

#### 1F component

```
DERIVED_KEY =  KMAC(key: FACTOR_KEYS[0], 
                    data: CTR_DATA)

MAC = KMAC(key: DERIVED_KEY, data: DATA)
```

#### 2F component

```
DERIVED_KEY = KMAC(key: FACTOR_KEYS[1],
                   data: CTR_DATA || 
                         KMAC(key: FACTOR_KEYS[0],
                              data: CTR_DATA))

MAC = KMAC(key: DERIVED_KEY, data: DATA)
```

#### 3F component

```
DERIVED_KEY = KMAC(key: FACTOR_KEYS[2], 
                   data: CTR_DATA ||
                         KMAC(key: FACTOR_KEYS[1],
                              data: CTR_DATA || 
                                    KMAC(key: FACTOR_KEYS[0],
                                         data: CTR_DATA)))
MAC = KMAC(key: DERIVED_KEY, data: DATA)    
```

## Validating the authentication code

### Constants and variables

The following constants and variables are involved in the authentication code validation:

- `CTR`, authentication code counter
	- Is a representation of logical time. Each parts in the scheme (client and server) increments the counter independently.
	- _Note: In protocols version `3` and above, the counter has only informational value and is no longer involved in the authentication code calculation. In protocol version `2`, the counter was directly involved in the authentication code calculation._
- `CTR_DATA`, hash based authentication code counter
	- Introduced in the protocol version `3`, now is used in the authentication code calculation.
	- It's randomly initialized and exchanged during the activation, or in the protocol upgrade process.
	- In protocol version `3.1+`, the client can synchronize its counter with the server.
- `CTR_LOOK_AHEAD`, tolerance set on server to overcome ahead clients
	- Server is trying to calculate and validate the authentication code ahead in time, in half-closed interval defined by this tolerance: `[CTR, CTR + CTR_LOOK_AHEAD)`.
	- Default value is `20`
- `FAILED_ATTEMPTS`, how many attempts failed before in row
	- Initial value is `0`.
	- If value reaches value defined in `MAX_FAILED_ATTEMPTS`, then activation is set to `BLOCKED` state.
	- Value is increased in case that authentication code validation fails (see description below)
- `MAX_FAILED_ATTEMPTS`, how many maximum failed attempts in a row result in blocked activation.
	- If `FAILED_ATTEMPTS` reaches this value, then activation is set to `BLOCKED` state.

### Algorithm

PowerAuth Server validates the authentication code using the following mechanism:

1. Find the activation record using activation ID.
1. Check the record state. If it is other than `ACTIVE`, or if a declared application version is unsupported, terminate the validation and report error.
1. Obtain `KEY_ACTIVATION_SECRET` for the activation (stored in encrypted form in the database).
1. Compute required factor keys (`KEY_AUTHENTICATION_CODE_POSSESSION`, `KEY_AUTHENTICATION_CODE_KNOWLEDGE` or `KEY_AUTHENTICATION_CODE_BIOMETRY`).
1. Compute the expected authentication code for obtained data and check if the expected authentication code matches the one sent with the client. Since the PowerAuth Client may be ahead with counter from PowerAuth Server, server should try couple extra indexes ahead:

```java
boolean verifyAuthenticationCode(byte[] data, List<SecretKey> factorKeys, int CTR, byte[] CTR_DATA, int CTR_LOOK_AHEAD) {
    boolean verified = false;
    byte[] CTR_DATA_ITER = CTR_DATA;
    for (int CTR_ITER = CTR; CTR_ITER++; CTR_ITER < CTR + CTR_LOOK_AHEAD) {
        //... compute authentication code for given CTR_DATA_ITER, data and
        //    factor keys (see the algorithm above)
        String AUTH_CODE = computeAuthenticationCode(data, factorKeys, CTR_DATA_ITER);
        if (AUTH_CODE.equals(AUTH_CODE_PROVIDED) && !VERIFIED) {
            verified = true;
            CTR_DATA = CTR_DATA_ITER; // ... also, persist CTR_DATA
            break;
        }
        // Move to the next hash-based counter's value
        CTR_DATA_ITER = Hash.sha3_256(CTR_DATA_ITER);
    }
    return verified;
}
```

#### Success

In case that authentication code is successfully verified, then:

- If authentication code is of a type `possession`, do NOT reset `FAILED_ATTEMPTS`.
- For other authentication code types than `possession`, reset the `FAILED_ATTEMPTS` to `0`.
- Move authentication code counter in database forward by setting `CTR` to `CTR_ITER` and `CTR_DATA` to `CTR_DATA_ITER`.

#### Failure

In case of failure:

- Increase the `FAILED_ATTEMPTS` value by `1`.
- If `FAILED_ATTEMPTS` is equal or greater than `MAX_FAILED_ATTEMPTS`, then set activation state to `BLOCKED`.
