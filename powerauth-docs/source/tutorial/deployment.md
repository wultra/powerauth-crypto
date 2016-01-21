# Deploying PowerAuth 2.0

This chapter explains how to deploy PowerAuth application stack in a simple infrastructure.

Following chapters are covered:

- [Deploying PowerAuth 2.0 Server](#deploying-powerauth-20-server)
- [Deploying PowerAuth 2.0 Standard RESTful API](#deploying-powerauth-20-standard-restful-api) (optional in production)
- [Integrating PowerAuth 2.0 with mobile API](#integrating-powerauth-20-with-mobile-api) (optional in testing)
- [Integrating PowerAuth 2.0 with internet banking](#integrating-powerauth-20-with-internet-banking) (optional in testing)
- [Testing the integration using PowerAuth 2.0 Reference Client](#testing-the-integration-using-powerauth-20-reference-client)

## Deploying PowerAuth 2.0 Server

PowerAuth 2.0 Server is a Java EE application (packaged as an executable WAR file) responsible for the PowerAuth 2.0 server-side cryptography implementation and data persistence. It exposes SOAP and RESTful API for the integrating applications (not end-user applications!), such as the internet banking or mobile banking API.

### Downloading PowerAuth 2.0 Server WAR

You can download the latest `powerauth-java-server.war` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

### Adding database connector on classpath

PowerAuth 2.0 Server supports any JPA 2.0 compatible database engine. In order for the database connectivity to work, you need to add appropriate DB client libraries on your classpath.

For example, when using MySQL with Tomcat, make sure to add `mysql-connector-java-${VERSION}.jar` to the `${CATALINE_HOME}/lib` folder (server restart will be required).

### Creating the database schema

In order for the PowerAuth 2.0 Server to work, you need to have a correct schema in the database. To create the correct database schema, execute these SQL scripts for your database engine (MySQL is used by default):

- [Default SQL Database Schema](https://github.com/lime-company/lime-security-powerauth/tree/master/powerauth-docs/sql)

### Connecting PowerAuth 2.0 Server to database

The default database connectivity parameters in `powerauth-java-server.war` are following (MySQL defaults):

```sh
spring.datasource.url=jdbc:mysql://localhost:3306/powerauth
spring.datasource.username=powerauth
spring.datasource.password=
spring.datasource.driver-class-name=com.mysql.jdbc.Driver
spring.jpa.hibernate.ddl-auto=none
```

These parameters are of course only for the testing purposes, they are not suitable for production environment. They should be overridden for your production environment using a standard [Spring database connectivity related properties](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html#boot-features-connect-to-production-database).

### Deploying PowerAuth 2.0 Server WAR file

You can deploy PowerAuth 2.0 Server WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-java-server/` (WSDL is then available on `http://localhost:8080/powerauth-java-server/powerauth/service.wsdl`).

To deploy PowerAuth 2.0 Server to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

### Deploying PowerAuth 2.0 Server outside the container

You can also execute PowerAuth 2.0 Server WAR file directly using the following command:

```bash
java -jar powerauth-java-server.war
```

_Note: If you launch both PowerAuth 2.0 Server and PowerAuth 2.0 Standard RESTful API using the 'java -jar' spell, you will get a conflict of the ports - only one application may use 8080 port at the time. You can overwrite the port using `-Dserver.port=8090` parameter_

## Deploying PowerAuth 2.0 Standard RESTful API

PowerAuth 2.0 Standard RESTful API is a Java EE application (packaged as an executable WAR file) responsible for exposing the [RESTful API according to the specification](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/api.md). It exposes services for end-user applications (PowerAuth 2.0 Clients), such as the mobile banking app or mobile token app.

### Configuring PowerAuth 2.0 Standard RESTful API

The default implementation of a PowerAuth 2.0 Standard RESTful API has only one proprietary configuration parameter `powerauth.service.url` that configures the SOAP endpoint location of a PowerAuth 2.0 Server. The default value for this property points to `localhost`:

```bash
powerauth.service.url=http://localhost:8080/powerauth-java-server/powerauth
```

### Downloading PowerAuth 2.0 Standard RESTful API

You can download the latest `powerauth-restful-server.war` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

### Deploying PowerAuth 2.0 Standard RESTful API

You can deploy PowerAuth 2.0 Standard RESTful API WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-restful-server/`.

To deploy PowerAuth 2.0 Standard RESTful API to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

### Deploying PowerAuth 2.0 Standard RESTful API outside the container

You can also execute WAR file directly using the following command:

```bash
java -jar powerauth-restful-server.war
```

_Note: If you launch both PowerAuth 2.0 Server and PowerAuth 2.0 Standard RESTful API using the 'java -jar' spell, you will get a conflict of the ports - only one application may use 8080 port at the time. You can overwrite the port using `-Dserver.port=8090` parameter_

## Integrating PowerAuth 2.0 with mobile API

Read the full tutorial here:

- [Integrate PowerAuth 2.0 Server with a mobile banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/mobile-api.md)

## Integrating PowerAuth 2.0 with internet banking

Read the full tutorial here:

- [Integrate PowerAuth 2.0 Server with an Internet banking server app](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/internet-banking.md)

## Testing the integration using PowerAuth 2.0 Reference Client

Read the full tutorial here:

- [Using PowerAuth 2.0 Reference Client](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/console-client-app.md)
