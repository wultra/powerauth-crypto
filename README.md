# PowerAuth 2.0

PowerAuth 2.0 is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth 2.0 protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## PowerAuth 2.0 Specification

- [Basic definitions](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/definitions.md)
- [Activation](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/activation.md)
- [Key Derivation](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/key-derivation.md)
- [Computing and Validating Signatures](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/signatures.md)
- [Standard RESTful API](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/api.md)
- [Implementation notes](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/notes.md)


## Integration tutorials

- [Integrate PowerAuth 2.0 Server with a mobile banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/mobile-api.md)
- [Integrate PowerAuth 2.0 Server with an Internet banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/internet-banking.md)

## How to build from sources

Project can be easily build using Maven with JDK 7 or 8.

```shell
$ git clone https://github.com/lime-company/lime-security-powerauth.git
$ cd lime-security-powerauth
$ mvn compile
```

In case you need to build project using IDE, make sure you are creating a new Maven project, not just a freeform project from existing sources. Maven is required since `powerauth-java-server` project uses [`jaxb2-maven-plugin`](http://www.mojohaus.org/jaxb2-maven-plugin/Documentation/v2.2/) to generate SOAP/REST transport object from an XSD file.

Source code include following Mavan modules under a single parent project:

- `powerauth-java` - Module responsible for the PowerAuth 2.0 cryptography implementation.
- `powerauth-java-client` - A simple SOAP service client class module capable of connecting to a running instance of PowerAuth 2.0 Server. This module is typically used to integrate with Master Front-End Application APIs, such as with internet banking application.
- `powerauth-java-cmd` - A command-line utility implementing a reference PowerAuth 2.0 Client.
- `powerauth-java-server` - A server application implementing a PowerAuth 2.0 Server. It is responsible for publishing PowerAuth 2.0 Server SOAP methods and RESTful API, and also for persistence of the data in a database.
- `powerauth-restful-model` - A simple module with the RESTful API model classes for PowerAuth 2.0 Standard RESTful API requests and responses.
- `powerauth-restful-security` - A module used to integrate PowerAuth 2.0 protocol in RESTful APIs. It includes PowerAuth 2.0 Standard RESTful API controllers (and therefore publishes related endpoints), `PowerAuthAuthenticationProvider` that can be used to verify signatures, utilities for correct configuration, etc. This module is typically used to integrate with Intermediate Server Application, such as mobile banking APIs.
- `powerauth-restful-server` - A simple implementation of the RESTful API publishing the PowerAuth 2.0 Standart RESTful API.

Maven modules have following dependencies:

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/maven-modules.png" width="100%"/>
