# Maven modules

PowerAuth 2.0 source code includes following Maven modules under a single parent project:

- `powerauth-java` - Module responsible for the PowerAuth 2.0 cryptography implementation.
- `powerauth-java-client` - A simple SOAP service client class module capable of connecting to a running instance of PowerAuth 2.0 Server. This module is typically used to integrate with Master Front-End Application APIs, such as with internet banking application.
- `powerauth-java-cmd` - A command-line utility implementing a reference PowerAuth 2.0 Client.
- `powerauth-java-server` - A server application implementing a PowerAuth 2.0 Server. It is responsible for publishing PowerAuth 2.0 Server SOAP methods and RESTful API, and also for persistence of the data in a database.
- `powerauth-restful-model` - A simple module with the RESTful API model classes for PowerAuth 2.0 Standard RESTful API requests and responses.
- `powerauth-restful-security` - A module used to integrate PowerAuth 2.0 protocol in RESTful APIs. It includes PowerAuth 2.0 Standard RESTful API controllers (and therefore publishes related endpoints), `PowerAuthAuthenticationProvider` that can be used to verify signatures, utilities for correct configuration, etc. This module is typically used to integrate with Intermediate Server Application, such as mobile banking APIs.
- `powerauth-restful-server` - A simple implementation of the RESTful API publishing the PowerAuth 2.0 Standart RESTful API.

Maven modules have following dependencies:

<img src="https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/export/maven-modules.png" width="100%"/>
