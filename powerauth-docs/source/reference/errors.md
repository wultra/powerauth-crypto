# PowerAuth 2.0 Server Error Codes

PowerAuth 2.0 Server may return following errors:

| Error Code | Error Message | Note |
|------------|---------------|------|
| ERR0000    | _Unknown error occurred._ | In case any unknown or low-level java error occurs, this exception is thrown. The original exception info is returned in the message |
| ERR0001    | No user ID was set. | Method, that requires user ID, was not provided with one. |
| ERR0002    | No application ID was set. | Method, that requires an application ID, was not provided with one. |
| ERR0003    | No master server key pair configured in database. | There is an issue with the database - an application does not have any master server key pair associated. This can happen only when manipulating with database manually or when there is a database consistency error. User PowerAuth 2.0 Admin to avoid this error. |
| ERR0004    | Master server key pair contains private key in incorrect format. | There is an issue with the database - an application has an associated master server key pair, but the format of this key is incorrect. This can happen only when manipulating with database manually or when there is a database consistency error. User PowerAuth 2.0 Admin to avoid this error. |
| ERR0005    | Too many failed attempts to generate activation ID. | In order to uniquely identify an activation, a random UUID (level 4) is generated as an activation ID. In a very unlikely case of a collision, server attempts to generate a new one, at most 10 times. When the new activation ID generation fails 10 times, this error is returned. |
| ERR0006    | Too many failed attempts to generate short activation ID. | In order to uniquely identify an activation during the activation process (client entering the activation code), a random activation code (2x5 characters in Base32 encoding) is generated as an activation short ID. In a very unlikely case of a collision (only CREATED and OTP_USED items can collide), server attempts to generate a new one, at most 10 times. When the new activation ID generation fails 10 times, this error is returned. |
| ERR0007    | This activation is already expired. | In case activation is in the state when it cannot be completed. This may be either due to time-out (activation was not committed fast enough) or in case someone tries to commit random / expired / blocked activations. |
| ERR0008    | Only activations in OTP_USED state can be committed. | When client attempts to commit an activation in any other state than OTP_USED, or when client attempts to commit a non-existing activation, this error is returned. |
| ERR0009    | Activation with given activation ID was not found. | Service didn't find an activation with given ID. |
| ERR0010    | Key with invalid format was provided. | In case the cryptographic method in initActivation method was provided with a key in incorrect format. |
| ERR0011    | Invalid input parameter format. | Provided data was not in a correct format. For example, values that were expected to be Base64 encoded or dates in specific date format were invalid. |
| ERR0012    | Invalid Signature Provided. | Signature verification failed since the verification process computed a different signature than the one that was provided by a client. |

For each of these issues, more details about the specific nature and cause can be found in the server log.
