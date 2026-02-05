# Activation Upgrade

This document describes how an existing PowerAuth activation is upgraded from protocol version 3 to protocol version 4.

The upgrade introduces new cryptographic algorithms, new factor keys, and a new shared secret. The process is authenticated and requires user presence (PIN / password, and optionally biometry).

Upgrade is performed transparently by the PowerAuth Client, typically right after activation status indicates that upgrade is available.

## Detecting Upgrade Availability

The PowerAuth Client determines whether an upgrade is available from the activation status blob. Upgrade is available for the application if the following condition is true:

- `CURRENT_VERSION` is `3` and `UPGRADE_VERSION` is `4`

## Overview

The V3 → V4 upgrade consists of two steps:

1. `/pa/v4/upgrade/start`
2. `/pa/v4/upgrade/confirm`

Both endpoints use end-to-end encryption.

High-level flow:

1. Client detects upgrade availability from activation status.
2. Client initiates upgrade by calling `/pa/v4/upgrade/start`.
3. Server and client establish a new `KEY_ACTIVATION_SECRET`, exchange new signing keys, and set the `STATUS_FLAG_UPGRADE_CONFIRMATION` flag to `true`.
4. Client migrates its local activation data to protocol V4.
5. Client finalizes upgrade by calling `/pa/v4/upgrade/confirm` using V4 authentication.
6. Server marks activation as protocol V4 and clears the `STATUS_FLAG_UPGRADE_CONFIRMATION` flag.

## Authenticated Upgrade

Upgrade to protocol version 4 is authenticated:

- `/pa/v4/upgrade/start` is authenticated with version 3 authentication code (possession_knowledge).
- `/pa/v4/upgrade/confirm` is authenticated with version 4 authentication code (possession factor).

Optionally, the biometric factor can be upgraded as part of the process.

## Upgrade Start

### Client

1. Client marks upgrade as in progress in persistent storage.
2. Client generates new signing key pairs (ECDSA / ML-DSA depending on algorithm).
3. Client prepares a shared-secret request.

4. Client sends request to `/pa/v4/upgrade/start`:

- Encrypted with E2EE V4, application scope
- `SHARED_INFO_1 = "/pa/upgrade/start"`
- Authenticated with V3 authentication code (`uriId = "/pa/upgrade/start"`)

Request body (before encryption):

```json
{
  "sharedSecretRequest": {
    "algorithm": "EC_P384_ML_L3",
    "encapsulationKeys": [ "Base64" ]
  },
  "devicePublicKeys": {
    "ecdsa": "Base64",
    "mldsa": "Base64"
  },
  "enableBiometry": true
}
```

### Server

On `/pa/v4/upgrade/start`:

1. Validate version 3 authentication code.
2. Decrypt request payload.
3. Reject request if activation is already upgraded.
4. Store the new device public keys.
5. Derive a new `KEY_ACTIVATION_SECRET` including all factor keys (biometry optional).
6. Set `STATUS_FLAG_UPGRADE_CONFIRMATION = 1` on activation record.
7. Configure the biometric factor based on request.
8. Prepare response payload:

```json
{
  "sharedSecretResponse": {
    "encapsulatedKeys": [ "Base64" ]
  },
  "serverPublicKeys": {
    "ecdsa": "Base64",
    "mldsa": "Base64"
  }
}
```

### Client (after response)

After receiving response from `/pa/v4/upgrade/start`, client:

1. Decrypts response.
2. Derives new `KEY_ACTIVATION_SECRET`.
3. Stores new server public keys.
4. Encrypts and stores newly generated private signing keys (using `KEK_DEVICE_PRIVATE`, AEAD).
5. Switches local activation to protocol V4.
6. Upgrades biometric KEK if biometry is enabled.

At this point, the client operates locally in protocol V4, but the server still awaits confirmation.

## Upgrade Confirm

### Client

Client sends request to `/pa/v4/upgrade/confirm`:

1. Authenticated with V4 authentication code (possession factor)
2. Request body is empty:

```json
{}
```

### Server

On `/pa/v4/upgrade/confirm`:

1. Verify that activation is awaiting upgrade confirmation.
2. Validate V4 authentication code.
3. Clear `STATUS_FLAG_UPGRADE_CONFIRMATION`.
4. Set activation protocol version to `4`.
5. Return:

```json
{
  "status": "OK"
}
```

### Client

After successful response:

1. Client clears the local "upgrade in progress" flag.
2. Upgrade is complete.

From this point on, all operations use protocol V4.

## Recovery From Failures

The upgrade process is resilient to network failures.

- Failure after `/pa/v4/upgrade/start` (the client did not receive response):
   - Client clears the local upgrade-in-progress flag.
   - Application retries upgrade from the beginning.

- Failure after `/pa/v4/upgrade/confirm` (the client did not receive response):
   - Client fetches activation status.
   - If the server already reports protocol V4, the client completes locally.
   - If the server is still V3 and `STATUS_FLAG_UPGRADE_CONFIRMATION` is set, client retries `/pa/v4/upgrade/confirm`.

## Special Situations

### Protocol Behavior Before Upgrade Completes

If the client supports version 4 but activation is still version 3:

- Authentication code uses protocol 3.3
- Token headers use protocol 3.3
- End-to-end encryption uses protocol 3.3

After the upgrade completes, all operations switch to protocol version` 4.

## Database Changes

On the server:

- `pa_activation.version` is set to `4` after successful upgrade.

## Biometry Key Migration

Protocol version 4 uses 256-bit keys instead of 128-bit keys.

If biometry is enabled:

### iOS

SDK generates a new 256-bit KEK and stores it in Keychain silently.

### Android

If `authenticateOnBiometricKeySetup` is enabled, user authentication is required to generate the new 256-bit key.
