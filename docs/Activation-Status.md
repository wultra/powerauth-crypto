# Activation Status

PowerAuth Client may need to check for an activation status, so that it can determine if it should display UI for non-activated state (registration form), blocked state (how to unblock tutorial) or active state (login screen). To facilitate this use-case, PowerAuth Standard RESTful API publishes a [/pa/activation/status](./Standard-RESTful-API.md#activation-status) endpoint.

## Flow of the Activation Status Check

Checking for an activation status is simple. Client needs to prepare a HTTP request with an activation ID. No cryptography is required in this step - in principle, any client can ask for status of any activation ID. Server processes the request and sends back the response with activation status blob. Activation status blob is an encrypted binary blob that encodes activation status. Key `KEY_TRANSPORT` is used to encrypt the activation blob.

Following sequence diagram shows the activation status check in more detail.

![Check Activation Status](./resources/images/sequence_activation_status.png)

## Status Blob Format

When obtaining the activation status, application receives the binary status blob. Structure of the 32B long status blob is following:

```
0xDEC0DED1 1B:${STATUS} 8B:${CTR} 1B:${FAIL_COUNT} 1B:${MAX_FAIL_COUNT} 17B:${RANDOM_NOISE}
```

where:

- The first 4 bytes (`0xDE 0xC0 0xDE 0xD1`) are basically a fixed prefix.
- `${STATUS}` - A status of the activation record, it can be one of following values:
    - `0x01 - CREATED`
    - `0x02 - OTP_USED`
    - `0x03 - ACTIVE`
    - `0x04 - BLOCKED`
    - `0x05 - REMOVED`
- `${CTR}` - 8 bytes representing information of the server counter (`CTR` value, as defined in PowerAuth specification).
- `${FAIL_COUNT}` - 1 byte representing information about the number of failed attempts at the moment.
- `${MAX_FAIL_COUNT}` - 1 byte representing information about the maximum allowed number of failed attempts.
- `${RANDOM_NOISE}` - Random 17 byte padding (a complement to the total length of 32B). These bytes also serve as a source of entropy for the transport (AES encrypted `cStatusBlob` will be different each time an endpoint is called).

For the purpose of a secure transport, the status blob is AES encrypted with `KEY_TRANSPORT`, like so:

- `encryptedStatusBlob = AES.encrypt(statusBlob, ByteUtils.zeroBytes(32), KEY_TRANSPORT, "AES/CBC/NoPadding")`

PowerAuth Client can later decrypt the original status blob:

- `statusBlob = AES.decrypt(encryptedStatusBlob, ByteUtils.zeroBytes(32), KEY_TRANSPORT, "AES/CBC/NoPadding")`
