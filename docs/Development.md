# Development

PowerAuth projects can be easily build using Maven with JDK 17 or higher (Java LTS release recommended).

To build PowerAuth server, use the following shell commands:

```shell
$ git clone https://github.com/wultra/powerauth-server.git
$ cd powerauth-server
$ mvn compile
```

To create a deployable .war file, use the following shell command:

```shell
$ mvn package
```

You can build all PowerAuth Java projects using similar steps:
- [PowerAuth Server](https://github.com/wultra/powerauth-server)
- [PowerAuth Admin](https://github.com/wultra/powerauth-admin)
- [PowerAuth Push Server](https://github.com/wultra/powerauth-push-server)
- [Enrollment Server](https://github.com/wultra/enrollment-server)
- [PowerAuth CMD Tool](https://github.com/wultra/powerauth-cmd-tool)
- [PowerAuth Crypto](./Readme.md)
- [PowerAuth Web Flow](https://github.com/wultra/powerauth-webflow)
- [SDK for RESTful APIs](https://github.com/wultra/powerauth-restful-integration)

<!-- begin box info -->
Note: Make sure you are creating a new Maven project in your IDE, not just a freeform project from existing sources. Maven is required for dependency management and for proper project building (for example, `powerauth-server` project uses [`jaxb2-maven-plugin`](http://www.mojohaus.org/jaxb2-maven-plugin/Documentation/v2.2/) to generate SOAP/REST transport object from an XSD file, etc.).
<!-- end -->

Read more about how Maven dependencies are organized at [Maven modules](./Maven-Modules.md) documentation.
