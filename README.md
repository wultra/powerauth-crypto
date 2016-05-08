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

- [Deploying PowerAuth 2.0 Server](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/deployment.md)
- [Deploying PowerAuth 2.0 Admin](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/deployment-admin.md)
- [Deploying PowerAuth 2.0 Standard RESTful API](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/deployment-rest-api.md)
- [Integrate PowerAuth 2.0 Server with a mobile banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/mobile-api.md)
- [Integrate PowerAuth 2.0 Server with an Internet banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/internet-banking.md)
- [Using PowerAuth 2.0 Reference Client](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/console-client-app.md)

## Reference manual

- [SOAP interface methods](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/reference/soap.md)
- [PowerAuth 2.0 Database Structure](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/reference/database.md)
- [PowerAuth 2.0 Server Error Codes](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/reference/errors.md)


## How to build from sources

Project can be easily build using Maven with JDK 7 or 8.

```shell
$ git clone https://github.com/lime-company/lime-security-powerauth.git
$ cd lime-security-powerauth
$ mvn compile
```

In case you need to build project using IDE, make sure you are creating a new Maven project, not just a freeform project from existing sources. Maven is required since `powerauth-java-server` project uses [`jaxb2-maven-plugin`](http://www.mojohaus.org/jaxb2-maven-plugin/Documentation/v2.2/) to generate SOAP/REST transport object from an XSD file.

Read more about how Maven dependencies are organized at [Maven modules](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/maven-modules.md) documentation.

# License

All sources are licensed using Apache license, you can use them with no restriction. If you are using PowerAuth 2.0, please let us know. We will be happy to share and promote your project.
