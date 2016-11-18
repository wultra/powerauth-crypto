# PowerAuth 2.0

[![SRC:CLR](https://img.shields.io/badge/SRC%3ACLR-passing-brightgreen.svg)](http://srcclr.com/)
[![Coverity Scan Build Status](https://img.shields.io/coverity/scan/8967.svg)](https://scan.coverity.com/projects/lime-company-lime-security-powerauth)
[![Build Status](https://travis-ci.org/lime-company/lime-security-powerauth.svg?branch=master)](https://travis-ci.org/lime-company/lime-security-powerauth)
[![GitHub issues](https://img.shields.io/github/issues/lime-company/lime-security-powerauth.svg?maxAge=2592000)](https://github.com/lime-company/lime-security-powerauth/issues)
[![Maven Central](https://img.shields.io/maven-central/v/io.getlime.security/powerauth-parent.svg?maxAge=2592000)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22io.getlime.security%22)
[![Twitter](https://img.shields.io/badge/twitter-@lime_company-blue.svg?style=flat)](http://twitter.com/lime_company)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/lime-company/lime-security-powerauth/blob/master/LICENSE.txt)

PowerAuth 2.0 is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth 2.0 protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## PowerAuth 2.0 Specification

- [Basic definitions](https://github.com/lime-company/lime-security-powerauth/wiki/Basic-definitions)
- [Activation](https://github.com/lime-company/lime-security-powerauth/wiki/Activation)
- [Key Derivation](https://github.com/lime-company/lime-security-powerauth/wiki/Key-derivation)
- [Computing and Validating Signatures](https://github.com/lime-company/lime-security-powerauth/wiki/Computing-and-Validating-Signatures)
- [Standard RESTful API](https://github.com/lime-company/lime-security-powerauth/wiki/Standard-RESTful-API)
- [Implementation details](https://github.com/lime-company/lime-security-powerauth/wiki/Implementation-notes)
- [List of used keys](https://github.com/lime-company/lime-security-powerauth/wiki/List-of-used-keys)


## Deployment tutorials

- [Deploying PowerAuth 2.0 Server](https://github.com/lime-company/lime-security-powerauth/wiki/Deploying-PowerAuth-2.0-Server)
- [Deploying PowerAuth 2.0 Admin](https://github.com/lime-company/lime-security-powerauth/wiki/Deploying-PowerAuth-2.0-Admin)
- [Deploying PowerAuth 2.0 Standard RESTful API](https://github.com/lime-company/lime-security-powerauth/wiki/Deploying-PowerAuth-2.0-Standard-RESTful-API)
- [Using PowerAuth 2.0 Reference Client](https://github.com/lime-company/lime-security-powerauth/wiki/Using-PowerAuth-2.0-Reference-Client)

## Integration tutorials

- [Overview of system integration](https://github.com/lime-company/lime-security-powerauth/wiki/Integration-tutorials)
- [Integrate PowerAuth 2.0 Server with a mobile banking server app](https://github.com/lime-company/lime-security-powerauth/wiki/Mobile-Banking-API)
- [Integrate PowerAuth 2.0 Server with an Internet banking server app](https://github.com/lime-company/lime-security-powerauth/wiki/Internet-banking-integration)

## Reference manual

- [SOAP interface methods](https://github.com/lime-company/lime-security-powerauth/wiki/SOAP-service-methods)
- [PowerAuth 2.0 Database Structure](https://github.com/lime-company/lime-security-powerauth/wiki/Database-Structure)
- [PowerAuth 2.0 Server Error Codes](https://github.com/lime-company/lime-security-powerauth/wiki/Server-Error-Codes)

# Development

In order to start developing PowerAuth 2.0, read our [Developer documentation](https://github.com/lime-company/lime-security-powerauth/wiki/Development).

# License

All sources are licensed using Apache 2.0 license, you can use them with no restriction. If you are using PowerAuth 2.0, please let us know. We will be happy to share and promote your project.
