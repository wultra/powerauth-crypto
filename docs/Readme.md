# PowerAuth Specification

PowerAuth is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or mobile identity applications. It defines all items that are required for a complete security solution: a used cryptography, associated processes, and standard RESTful API end-points.

A typical use-case for PowerAuth protocol would be assuring the security of mobile banking application. Users usually download a "blank" (non-personalized) mobile banking app from the mobile application markets, such as Google Play or App Store. Then, they activate (personalize, register, ...) the mobile banking app using credentials that are assumed sufficient for this purpose, for example via the QR code displayed in the internet banking, the branch kiosk system, ATM, or hardware authenticator. Only after this process is completed, users can use activated mobile banking app to create signed requests - to log in to mobile banking, send payments, certify contracts, etc.

The PowerAuth protocol also defines additional features, such as end-to-end encryption or secure storage through the secure vault. Unlike the authentication, these features do not constitute the protocol primary use-case and they mostly play a supportive role.

<!-- begin box info -->
For any questions related to the protocol, please write to [hello@wultra.com](mailto:hello@wultra.com). If you believe you have identified a security vulnerability with PowerAuth, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
<!-- end -->
