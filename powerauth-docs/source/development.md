# Development

Project can be easily build using Maven with JDK 7 or 8.

```shell
$ git clone https://github.com/lime-company/lime-security-powerauth.git
$ cd lime-security-powerauth
$ mvn compile
```

In case you need to build project using IDE, make sure you are creating a new Maven project, not just a freeform project from existing sources. Maven is required since `powerauth-java-server` project uses [`jaxb2-maven-plugin`](http://www.mojohaus.org/jaxb2-maven-plugin/Documentation/v2.2/) to generate SOAP/REST transport object from an XSD file.

Read more about how Maven dependencies are organized at [Maven modules](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/maven-modules.md) documentation.
