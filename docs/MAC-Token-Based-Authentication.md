# MAC Token Based Authentication

While standard PowerAuth signatures are suitable for requests where a high degree of authenticity and integrity is required, for high-volume common access requests, the strong sequentiality caused by the use of a counter might be too restricting. Signed requests must be sent one by one, and a request needs to wait for the previous one to complete. This causes both data processing to be slow and the programming task related to request synchronization to be unnecessarily difficult.

This is why PowerAuth also supports simplified MAC Token-Based Authentication. As the name suggests, the authentication is achieved by computing a MAC (also called a "digest") using a pre-shared token.

## Security Considerations

There are a couple of very important things to keep in mind while using MAC Token-Based Authentication in your APIs:

- **Data Integrity** - Since the resulting digest does not include any request data, it does not prevent data from being modified.
- **Single Factor** - While the token has information about the factors used while the token was created, which is handy while distinguishing different grades of information (for example, some more sensitive info may require a token that was created using 2FA), the authentication as such uses only a single factor. It does not include PIN/password or biometric information at all.

As a result, you must use MAC Token-Based Authentication for read-only operations only. In other words, use the MAC Token-Based Authentication to access resources, not to create or modify them. We recommend using the 1FA PowerAuth signature for active operations that create or modify resources but do not require user's interaction. This way, you avoid having repeated or inconsistent data while allowing access to information that needs to be frequently accessed.

Examples:

**MAC Token-Based Authentication**

Accessing simple information about the account, such as account name, balance of the account, and last three transactions, from Apple Watch.

**PowerAuth 1FA Signature**

Creating a quick, low-value payment from an iPhone app.

## Creating a Token

In order to create a new token, the client application must call a PowerAuth Standard RESTful API endpoint `/pa/v3/token/create`.

This endpoint must be called with a standard PowerAuth signature. It can be any type of signature - 1FA or 2FA. The token then implicitly carries the information about the signature it was issued with. Using the PowerAuth signature assures the authenticity and integrity of the data sent during the request.

The endpoint then uses the same request and response encryption principles as described in a dedicated chapter for [End-to-End Encryption](./End-To-End-Encryption.md).

Upon receiving and successfully validating a request authenticated using a PowerAuth signature, the server generates a new token for a given activation ID. Information about the used signature type and factors are stored with the token. Then, the server takes the token ID and secret and sends them in an ECIES encrypted response to the client.

The decrypted response data payload contains the following raw response format:

```json
{
   "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb",  
   "tokenSecret": "VqAXEhziiT27lxoqREjtcQ=="
}
```

The `tokenId` value is in UUID level 4 format, and it uniquely identifies the token in the system and is sent with every request that requires MAC token-based authentication. The `token_secret` value is a random 16B value encoded as Base64. It is stored on the device and used as a secret key for computing the MAC later.

The client stores both `token_id` and `token_secret` in a suitable local storage (iOS Keychain, encrypted Shared Preferences).

## Using the Tokens

When using MAC Token-Based Authentication, the authentication of the RESTful API calls is achieved by computing a `token_digest` digest value on the client side that can be later validated on the server side. The algorithms for calculation and verification of the digest are, in principle, the same.

The `token_digest` value is computed using the following algorithm:

```java
// '$timestamp' is a Unix timestamp in milliseconds (to achieve the required time
//             precision) converted to a string and then to byte[] using UTF-8
//             encoding
// '$version' is the protocol version, represented as UTF-8 bytes of the version string
long timestamp = Time.getTimestamp();
byte[] timestamp_bytes = ByteUtils.encode(String.valueOf(timestamp));

// '$nonce' value is 16B of random data
byte[] nonce = Generator.randomBytes(16);

// '$nonce' is concatenated to '$timestamp' and '$version' using '&' character:
//    $nonce + '&' + $timestamp + '&' + $version
byte[] data = ByteUtils.concat(nonce, ByteUtils.encode("&"), timestamp_bytes, ByteUtils.encode("&"), version);

// 'token_secret' is 16B of random data
SecretKey key = KeyConversion.secretKeyFromBytes(token_secret);

// Compute the digest using HMAC-SHA256
byte[] token_digest = Mac.hmacSha256(key, data)
```

In order to use the token authentication with the RESTful API call, you need to set the following HTTP header to the request:

```
X-PowerAuth-Token: PowerAuth token_id="${TOKEN_ID}"
    token_digest="${TOKEN_DIGEST}"
    nonce="${NONCE}"
    timestamp="${TIMESTAMP}"
    version="3.2"
```

Transport representation of the HTTP header properties is following:

- `token_id` - Identifier of the token, as is - UUID level 4.
- `token_digest` - Digest value computed using `token_secret`, `nonce`, and `timestamp`, Base64 encoded.
- `nonce` - Random cryptographic nonce, 16B long, Base64 encoded.
- `timestamp` - Current timestamp in a Unix timestamp format (in milliseconds, to achieve required time precision), represented as a string value.
- `version` - Protocol version.

## Token Removal

You can remove a token with a given ID anytime by sending a signed request to the PowerAuth Standard RESTful API endpoint `/pa/v3/token/remove`:

```json
{
    "requestObject": {
        "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
    }
}
```

You can use any signature type to authenticate the token removal request. All signature types are allowed because the tokens are mostly used for simplified access. Allowing the user to restrict the access again should be simple, as long as there is at least some authentication that would prevent removing token to the malicious party (causing DoS to the legitimate user).

If the signature validation is successful and after validating that the token is associated with the activation used for computing the signature, the token is removed on the server side. The response object only confirms the removal and the payload is typically ignored in the PowerAuth Mobile SDK:

```json
{
    "requestObject": {
        "tokenId": "d6561669-34d6-4fee-8913-89477687a5cb"
    }
}
```
