# PowerAuth

PowerAuth is a protocol for key exchange and subsequent request signing, designed specifically for applications with high security requirements, such as banking or mobile identity applications. It defines all items required for a complete security solution: cryptographic algorithms, associated processes, and standard RESTful API endpoints.

A typical use case for the PowerAuth protocol would be assuring the security of a mobile banking application. Users usually download a "blank" (non-personalized) mobile banking app from app stores, such as Google Play or the App Store. Then, they activate (personalize, register, ...) the mobile banking app using credentials that are assumed sufficient for this purpose, for example, via the QR code displayed in internet banking, the branch kiosk system, an ATM, or a hardware authenticator. Only after this process is completed, users can use the activated mobile banking app to create signed requests - to log in to mobile banking, send payments, certify contracts, etc.

The PowerAuth protocol also defines additional features, such as end-to-end encryption or secure storage through the secure vault. Unlike authentication, these features do not constitute the protocol's primary use case; they mostly serve a supporting role.

<!-- begin box info -->
For any questions related to the protocol, please write to [hello@wultra.com](mailto:hello@wultra.com). If you believe you have identified a security vulnerability with PowerAuth, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
<!-- end -->

## Protocol Versions

| Feature                   | Crypto 3.2 | Crypto 3.3 | Crypto 4.0 |
|---------------------------|:----------:|:----------:|:----------:|
| Simplified Configuration  | ✅          | ✅         | ✅          |
| Strict uniqueness checks  | ✅          | ✅         | ✅          |
| Time Synchronization      | ✅          | ✅         | ✅          |
| Strict forward secrecy    |             | ✅          | ✅          |
| PQC-Ready                 |             |            | ✅          |
| Dynamic factor keys       |             |            | ✅          |
| Reduced vault usage       |             |            | ✅          |
