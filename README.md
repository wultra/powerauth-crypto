# PowerAuth

[![Coverity Scan Build Status](https://img.shields.io/coverity/scan/8967.svg)](https://scan.coverity.com/projects/wultra-powerauth-crypto)
[![Build Status](https://travis-ci.org/wultra/powerauth-crypto.svg?branch=master)](https://travis-ci.org/wultra/powerauth-crypto)
[![GitHub issues](https://img.shields.io/github/issues/wultra/powerauth-crypto.svg?maxAge=2592000)](https://github.com/wultra/powerauth-crypto/issues)
[![Maven Central](https://img.shields.io/maven-central/v/io.getlime.security/powerauth-java-crypto.svg?maxAge=2592000)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22io.getlime.security%22)
[![Twitter](https://img.shields.io/badge/twitter-@wultra-blue.svg?style=flat)](http://twitter.com/wultra)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wultra/powerauth-crypto/blob/master/LICENSE.txt)

PowerAuth is a protocol for a key exchange and for subsequent request signing designed specifically for the purposes of applications with high security demands, such as banking applications or identity management applications. It defines all items that are required for a complete security solution: a used cryptography, a security scheme and standard RESTful API end-points.

A typical use-case for PowerAuth protocol would be assuring the security of a mobile banking application. User usually downloads a "blank" (non-personalized) mobile banking app from the mobile application market. Then, user activates (personalizes, using a key-exchange algorithm) the mobile banking using some application that is assumed secure, for example via the internet banking or via the branch kiosk system. Finally, user can use activated mobile banking application to create signed requests - to log in to mobile banking, send a payment, certify contracts, etc.

## Documentation

For the most recent documentation and tutorials, please [visit our Wiki](https://github.com/wultra/powerauth-crypto/wiki).

# License

All sources are licensed using Apache 2.0 license, you can use them with no restriction. If you are using PowerAuth, please let us know. We will be happy to share and promote your project.
