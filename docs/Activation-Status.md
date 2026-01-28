# Activation Status

PowerAuth Client may need to check for an activation status, so that it can determine if it should display UI for non-activated state (registration form), blocked state (how to unblock tutorial) or active state (login screen). To facilitate this use-case, PowerAuth Standard RESTful API publishes a `/pa/activation/status` endpoint.

Checking activation status is performed over standard end-to-end encryption with a temporary activation-scoped key. The legacy STATUS_CHALLENGE / STATUS_NONCE transport is no longer used.

The server returns a Base64-encoded binary activation status blob that is integrity protected with KMAC and transported inside the encrypted response.

## Status Check Sequence

The client calls the activation status endpoint with an empty request body using standard end-to-end encryption.

Response body (before encryption):

```json
{
  "activationStatus": "BASE64",
  "customObject": {
    "_comment": "Any optional service data"
  }
}
```

Activation status uses activation-scoped end-to-end encryption with SHARED_INFO_1 = "/pa/activation/status".

## Status Blob Format

The final binary status blob is:

```java
byte[] BINARY_STATUS_BLOB = ByteUtils.concat(STATUS_DATA, STATUS_MAC);
```

### STATUS_DATA

Binary layout:

```
4B:  0xDEC0DED4
1B:  ${STATUS}
1B:  ${CURRENT_VERSION}
1B:  ${UPGRADE_VERSION}
1B:  ${STATUS_FLAGS}
4B:  ${RESERVED}
1B:  ${CTR_BYTE}
1B:  ${FAIL_COUNT}
1B:  ${MAX_FAIL_COUNT}
1B:  ${CTR_LOOK_AHEAD}
32B: ${CTR_DATA_HASH}
```

Note: Magic prefix changed from `0xDEC0DED1` to `0xDEC0DED4` to indicate the newest status blob format.

### STATUS_MAC

Integrity protection:

```java
byte[] STATUS_MAC = Mac.kmac256(KEY_MAC_STATUS, STATUS_DATA, 32, "PA4MAC-STATUS");
```

Where:

```java
SecretKey KDK_UTILITY     = KDF.derive(KEY_ACTIVATION_SECRET, "util");
SecretKey KEY_MAC_STATUS = KDF.derive(KDK_UTILITY, "util/mac/status");
```

Note: Even though the blob is delivered over end-to-end encryption, it is additionally authenticated with STATUS_MAC.

## Status Fields

### STATUS

- `0x01` – CREATED
- `0x02` – PENDING_COMMIT
- `0x03` – ACTIVE
- `0x04` – BLOCKED
- `0x05` – REMOVED

### CURRENT_VERSION

Current protocol version of the activation.

### UPGRADE_VERSION

Maximum protocol version supported by the server for this activation.

### STATUS_FLAGS

Bitmask:

- bit 0 – `STATUS_FLAG_ACTIVATION_CONFIRMATION` – pending client confirmation
- bit 1 – `STATUS_FLAG_UPGRADE_CONFIRMATION` – pending upgrade confirmation
- bit 2 – `STATUS_FLAG_UNSUPPORTED_ALGORITHM` – activation uses unsupported algorithm
- bit 3 – `STATUS_FLAG_BIOMETRY_FACTOR_ON` – biometry factor enabled on server

Flag explanation:

Client should treat activation as upgradeable if `CURRENT_VERSION` differs from `UPGRADE_VERSION`.

The `STATUS_FLAG_UNSUPPORTED_ALGORITHM` is used to denote that the algorithm used to create the activation is no longer supported.

Pending activation confirmation is indicated by `STATUS_FLAG_ACTIVATION_CONFIRMATION`.

Pending upgrade confirmation is indicated by `STATUS_FLAG_UPGRADE_CONFIRMATION`.

### CTR_BYTE

Least significant byte of current counter:

```java
byte CTR_BYTE = (byte)(CTR & 0xFF);
```

### Counters

Counter explanation:

- `FAIL_COUNT` = current failed attempts
- `MAX_FAIL_COUNT` = maximum allowed attempts
- `CTR_LOOK_AHEAD` = look-ahead window for server-side validation

### CTR_DATA_HASH

32-byte hash of the hash-based counter is calculated like this:

```java
byte[] CTR_DATA_HASH = Mac.kmac256(CTR_DATA, KEY_MAC_CTR_DATA, 32, "PA4MAC-CTR");
```

The key for counter data is obtained as follows:

```java
SecretKey KDK_UTILITY      = KDF.derive(KEY_ACTIVATION_SECRET, "util");
SecretKey KEY_MAC_CTR_DATA = KDF.derive(KDK_UTILITY, "util/mac/ctr-data");
```


