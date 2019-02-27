# PowerAuth Specification

PowerAuth is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

The protocol also supports end-to-end encryption and secure storage. Unlike the authentication, these features are currently experimental and require better validation by the cryptography experts and market.

Following chapters describe the cryptography that is used in PowerAuth.

- [Basic Definitions](./Basic-definitions.md) - Explains the basic terminology used in the documentation.
- [Activation](./Activation.md) - Describes the activation ("personalization") process.
- [Key Derivation](./Key-derivation.md) - Explains what keys are derived after the base activation key exchange.
- [Checking Activation Status](./Activation-Status.md) - Explains how client can fetch information about given activation.
- [Computing and Validating Signatures](./Computing-and-Validating-Signatures.md) - Shows how signatures are computed and validated.
- [End-To-End Encryption](./End-To-End-Encryption.md) - Explains personalized and non-personalized encryption.
- [List of Used Keys](./List-of-used-keys.md) - Lists all keys that are used in the PowerAuth protocol.

These additional chapters provide additional insight in the practical protocol implementation.

- [Standard RESTful API](./Standard-RESTful-API.md)
- [Implementation Details](./Implementation-notes.md)

For any questions related to the protocol, please write to hello@wultra.com.
