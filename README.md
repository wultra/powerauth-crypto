# PowerAuth 2.0

PowerAuth 2.0 is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth 2.0 protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## PowerAuth 2.0 Specification

- [[Basic definitions|Basic-definitions]]
- [[Activation|Activation]]
- [[Key Derivation|Key-derivation]]
- [[Computing and Validating Signatures|Computing-and-validating-signatures]]
- [[Standard RESTful API|Standard-restful-api]]
- [[Implementation notes|Implementation-notes]]

## Deployment tutorials

- [[Deploying PowerAuth 2.0 Server|Deploying-PowerAuth-2.0-Server]]
- [[Deploying PowerAuth 2.0 Admin|Deploying-PowerAuth-2.0-Admin]]
- [[Deploying PowerAuth 2.0 Standard RESTful API|Deploying-PowerAuth-2.0-Standard-RESTful-API]]
- [[Using PowerAuth 2.0 Reference Client|Using-PowerAuth-2.0-Reference-Client]]

## Integration tutorials

- [[Integrate PowerAuth 2.0 Server with a mobile banking server app|Mobile-Banking-API]]
- [[Integrate PowerAuth 2.0 Server with an Internet banking server app|Internet-banking-integration]]

## Reference manual

- [[SOAP interface methods|SOAP-service-methods]]
- [[PowerAuth 2.0 Database Structure|Database-Structure]]
- [[PowerAuth 2.0 Server Error Codes|Server-Error-Codes]]

# Development

In order to start developing PowerAuth 2.0, read our [[Developer documentation|Development]].

# License

All sources are licensed using Apache license, you can use them with no restriction. If you are using PowerAuth 2.0, please let us know. We will be happy to share and promote your project.
