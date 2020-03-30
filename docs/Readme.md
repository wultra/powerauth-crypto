# PowerAuth

PowerAuth is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## PowerAuth Specification

- [Basic Definitions](./Basic-definitions.md)
- [Activation](./Activation.md)
- [Key Derivation](./Key-derivation.md)
- [Checking Activation Status](./Activation-Status.md)
- [Computing and Validating Signatures](./Computing-and-Validating-Signatures.md)
- [MAC Token Based Authentication](./MAC-Token-Based-Authentication.md)
- [End-To-End Encryption](./End-To-End-Encryption.md)
- [Activation Recovery](Activation-Recovery.md)
- [Additional Activation OTP](Additional-Activation-OTP.md)
- [Standard RESTful API](./Standard-RESTful-API.md)
- [Implementation Details](./Implementation-notes.md)
    - [Activation Code](./Activation-Code.md)
    - [Activation Upgrade](./Activation-Upgrade.md)
- [List of Used Keys](./List-of-used-keys.md)

## Deployment

- [Deployment Checklist](./Deployment-Checklist.md)
- [Architecture Overview](./Architecture-Overview.md)

## Applications

- [PowerAuth Server](https://github.com/wultra/powerauth-server)
- [PowerAuth Admin](https://github.com/wultra/powerauth-admin)
- [PowerAuth Push Server](https://github.com/wultra/powerauth-push-server)
- [PowerAuth Command-Line Tool](https://github.com/wultra/powerauth-cmd-tool)
- [PowerAuth Mobile SDK for iOS and Android](https://github.com/wultra/powerauth-mobile-sdk)
- [Integration Libraries for RESTful APIs](https://github.com/wultra/powerauth-restful-integration)

## Releases

- [List of Releases](./Releases.md)

# Development

In order to start developing PowerAuth, read our [Developer documentation](./Development.md).
