# Deploying PowerAuth 2.0 Standard RESTful API

This chapter explains how to deploy PowerAuth 2.0 Standard RESTful API.

PowerAuth 2.0 Standard RESTful API is a Java EE application (packaged as an executable WAR file) responsible for exposing the [RESTful API according to the specification](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/api.md). It exposes services for end-user applications (PowerAuth 2.0 Clients), such as the mobile banking app or mobile token app.

You can use this application in case you need to use PowerAuth 2.0 with application that cannot integrate with PowerAuth 2.0 Security Spring libraries.

## Downloading PowerAuth 2.0 Standard RESTful API

You can download the latest `powerauth-restful-server.war` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

## Configuring PowerAuth 2.0 Standard RESTful API

The default implementation of a PowerAuth 2.0 Standard RESTful API has only one proprietary configuration parameter `powerauth.service.url` that configures the SOAP endpoint location of a PowerAuth 2.0 Server. The default value for this property points to `localhost`:

```bash
powerauth.service.url=http://localhost:8080/powerauth-java-server/soap
```

## Deploying PowerAuth 2.0 Standard RESTful API

You can deploy PowerAuth 2.0 Standard RESTful API WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-restful-server/`.

To deploy PowerAuth 2.0 Standard RESTful API to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

## Deploying PowerAuth 2.0 Standard RESTful API outside the container

You can also execute WAR file directly using the following command:

```bash
java -jar powerauth-restful-server.war
```

_Note: You can overwrite the port using `-Dserver.port=8090` parameter to avoid port conflicts._
