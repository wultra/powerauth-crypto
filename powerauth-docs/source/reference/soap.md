# SOAP service methods

This is a reference documentation of the methods published by the PowerAuth 2.0 Server SOAP service. It reflects the SOAP service methods as they are defined in the [WSDL file](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-java-client/src/main/resources/soap/wsdl/service.wsdl).

Following methods are published using the service:

- System status
    - getStatus
- Application management
    - getApplicationList
    - getApplicationDetail
    - createApplication
    - createApplicationVersion
    - unsupportApplicationVersion
    - supportApplicationVersion
- Activation management
    - getActivationListForUser
    - initActivation
    - prepareActivation
    - commitActivation
    - getActivationStatus
    - removeActivation
    - blockActivation
    - unblockActivation
- Signature verification
    - verifySignature
- Vault unlocking
    - vaultUnlock
- Signature audit log
    - getSignatureAuditLog

## System status

Methods used for getting the PowerAuth 2.0 Server system status.

### Method 'getStatus'

Get the server status information.

#### Request

`GetSystemStatusRequest`

- _no attributes_

#### Response

`GetSystemStatusResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `status` | A constant value "OK". |
| `String` | `applicationName` | A name of the application, the default value is `powerauth`. The value may be overriden by setting`powerauth.service.applicationName` property.
| `String` | `applicationDisplayName` | A human readable name of the application, default value is "PowerAuth 2.0 Server". The value may be overriden by setting `powerauth.service.applicationDisplayName` property. |
| `String` | `applicationEnvironment` | An identifier of the environment, by default, the value is empty. The value may be overriden by setting `powerauth.service.applicationEnvironment` property. |
| `DateTime` | `timestamp` | A current system timestamp.""

## Application management

Methods related to the management of applications and application versions.

### Method 'getApplicationList'

Get list of all applications that are present in this PowerAuth 2.0 Server instance.

#### Request

`GetApplicationListRequest`

- _no attributes_

#### Response

`GetApplicationListRequest`

| Type | Name | Description |
|------|------|-------------|
| `Application[]` | `applications` | A collection of application objects |

`GetApplicationListRequest.Application`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | An application ID |
| `String` | `applicationName` | Application name |

### Method 'getApplicationDetail'

Get detail of application with given ID, including the list of versions.

#### Request

`GetApplicationDetailRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |

#### Response

`GetApplicationDetailResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |
| `String` | `masterPublicKey` | Base64 encoded master public key |
| `Version[]` | `versions` | Collection of application versions |

`GetApplicationDetailResponse.Version`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name, for example "1.0.3" |
| `String` | `applicationKey` | An application key associated with this version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'createApplication'

Create a new application with given name.

#### Request

`CreateApplicationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `applicationName` | An application name |

#### Response

`CreateApplicationResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationName` | An application name |

### Method 'createApplicationVersion'

Create a new application version with given name for a specified application.

#### Request

`CreateApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | An identifier of an application |
| `String` | `applicationVersionName` | An application version name |

#### Response

`CreateApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `String` | `applicationVersionName` | An application version name |
| `String` | `applicationKey` | An application key associated with this version |
| `String` | `applicationSecret` | An application secret associated with this version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'unsupportApplicationVersion'

Mark application version with given ID as "unsupported". Signatures constructed using application key and application secret associated with this versions will be rejected as invalid.

#### Request

`UnsupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response

`UnsupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

### Method 'supportApplicationVersion'

Mark application version with given ID as "supported". Signatures constructed using application key and application secret associated with this versions will be evaluated the standard way.

#### Request

`SupportApplicationVersionRequest`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |

#### Response

`SupportApplicationVersionResponse`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | An identifier of an application version |
| `Boolean` | `supported` | Flag indicating if this application is supported |

## Activation management

Methods related to activation management.

### Method 'getActivationListForUser'

Get the list of all activations for given user and application ID. If no application ID is provided, return list of all activations for given user.

#### Request

`GetActivationListForUserRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |

#### Response

`GetActivationListForUserResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Activation[]` | `activations` | A collection of activations for given user |

`GetActivationListForUserResponse.Activation`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `activationName` | An activation name |
| `String` | `extras` | Any custom attributes |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `applicationName` | An application name |

### Method 'initActivation'

Create (initialize) a new application for given user and application. After calling this method, a new activation record is created in CREATED state.

#### Request

`InitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampActivationExpire` | Timestamp after when the activation cannot be completed anymore |
| `Long` | `maxFailureCount` | How many failures are allowed for this activation |

#### Response

`InitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A long UUID4 identifier of an activation |
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationOTP` | An activation OTP (5+5 characters from Base32) |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |

### Method 'prepareActivation'

Assure a key exchange between PowerAuth 2.0 Client and PowerAuth 2.0 Server and prepare the activation with given ID to be committed. Only activations in CREATED state can be prepared. After successfully calling this method, activation is in OTP_USED state.

#### Request

`PrepareActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationName` | A visual identifier of the activation |
| `String` | `extras` | Any extra parameter object |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `encryptedDevicePublicKey` | A base64 encoded encrypted device public key |
| `String` | `applicationKey` | An application key |
| `String` | `applicationSignature` | An application signature |

#### Response

`PrepareActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | A long UUID4 identifier of an activation |
| `String` | `activationNonce` | A base64 encoded activation nonce |
| `String` | `ephemeralPublicKey` | A base64 encoded ephemeral public key |
| `String` | `encryptedServerPublicKey` | A base64 encoded encrypted server public key |
| `String` | `encryptedServerPublicKeySignature` | A base64 encoded signature of the activation data using Master Server Private Key |

### Method 'commitActivation'

Commit activation with given ID. Only non-expired activations in OTP_USED state can be committed. After successful commit, activation is in ACTIVE state.

#### Request

`CommitActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`CommitActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `activated` | Flag indicating if the activation was committed |

### Method 'getActivationStatus'

Get status information and all important details for activation with given ID.

#### Request

`GetActivationStatusRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`GetActivationStatusResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |
| `String` | `activationName` | An activation name |
| `String` | `userId` | An identifier of a user |
| `String` | `extras` | Any custom attributes |
| `Long` | `applicationId` | An identifier fo an application |
| `String` | `encryptedStatusBlob` | An encrypted blob with status information |
| `DateTime` | `timestampCreated` | A timestamp when the activation was created |
| `DateTime` | `timestampLastUsed` | A timestamp when the activation was last used |
| `String` | `activationIdShort` | A short (5+5 characters from Base32) identifier of an activation |
| `String` | `activationOTP` | An activation OTP (5+5 characters from Base32) |
| `String` | `activationSignature` | A signature of the activation data using Master Server Private Key |

### Method 'removeActivation'

Remove activation with given ID. This operation is irreversible. Activations can be removed in any state. After successfully calling this method, activation is in REMOVED state.

#### Request

`RemoveActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`RemoveActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `Boolean` | `removed` | Flag indicating if the activation was removed |

### Method 'blockActivation'

Block activation with given ID. Activations can be blocked in ACTIVE state only. After successfully calling this method, activation is in BLOCKED state.

#### Request

`BlockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`BlockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |

### Method 'unblockActivation'

Unblock activation with given ID. Activations can be unblocked in BLOCKED state only. After successfully calling this method, activation is in ACTIVE state and failed attempt counter is set to 0.

#### Request

`UnblockActivationRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |

#### Response

`UnblockActivationResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `ActivationStatus` | `activationStatus` | An activation status |

## Signature verification

Methods related to signature verification.

### Method 'verifySignature'

Verify signature correctness for given activation, application key, data and signature type.

#### Request

`VerifySignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | An key (identifier) of an application, associated with given application version |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth 2.0 signature |
| `String` | `signatureType` | PowerAuth 2.0 signature type |

#### Response

`VerifySignatureRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `ActivationStatus` | `activationStatus` | An activation status |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |

## Vault unlocking

Methods related to secure vault.

### Method 'vaultUnlock'

Get the encrypted vault unlock key upon successful authentication using PowerAuth 2.0 Signature.

#### Request

`VaultUnlockRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `applicationKey` | An key (identifier) of an application, associated with given application version |
| `String` | `data` | Base64 encoded data for the signature |
| `String` | `signature` | PowerAuth 2.0 signature |
| `String` | `signatureType` | PowerAuth 2.0 signature type |

#### Response

`VaultUnlockResponse`

| Type | Name | Description |
|------|------|-------------|
| `String` | `activationId` | An identifier of an activation |
| `String` | `userId` | An identifier of a user |
| `ActivationStatus` | `activationStatus` | An activation status |
| `Integer` | `remainingAttempts` | How many attempts are left for authentication using this activation |
| `Boolean` | `signatureValid` | Indicates if the signature was correctly validated or if it was invalid (incorrect) |
| `String` | `encryptedVaultEncryptionKey` | Encrypted key for vault unlocking |

## Signature audit

Methods related to signature auditing.

### Method 'getSignatureAuditLog'

Get the signature audit log for given user, application and date range. In case no application ID is provided, event log for all applications is returned.

#### Request

`SignatureAuditRequest`

| Type | Name | Description |
|------|------|-------------|
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `DateTime` | `timestampFrom` | Timestamp from which to fetch the log |
| `DateTime` | `timestampTo` | Timestamp to which to fetch the log |

#### Response

`SignatureAuditResponse`

| Type | Name | Description |
|------|------|-------------|
| `Item[]` | `items` | Collection of signature audit logs |

`SignatureAuditResponse.Item`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `id` | Record ID |
| `String` | `userId` | An identifier of a user |
| `Long` | `applicationId` | An identifier of an application |
| `String` | `activationId` | An identifier of an activation |
| `Long` | `activationCounter` | A counter value at the moment of a signature verification |
| `ActivationStatus` | `activationStatus` | An activation status at the moment of a signature verification |
| `String` | `dataBase64` | A base64 encoded data sent with the signature |
| `String` | `signatureType` | Requested signature type |
| `String` | `signature` | Submitted value of a signature |
| `String` | `note` | Extra info about the result of the signature verification |
| `Boolean` | `valid` | Flag indicating if the provided signature was valid |
| `DateTime` | `timestampCreated` | Timestamp when the record was created |

## Used enums

This chapter lists all enums used by PowerAuth 2.0 Server SOAP service.

- `ActivationStatus` - Represents the status of activation, one of following values:
    - CREATED
    - OTP_USED
    - ACTIVE
    - BLOCKED
    - REMOVED

## Documentation template

When adding documentation for a new method, use this template:

### Method 'methodName'

#### Request

`RequestObject`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationId` | Lorem ipsum |

#### Response

`ResponseObject`

| Type | Name | Description |
|------|------|-------------|
| `Long` | `applicationVersionId` | Lorem ipsum |
