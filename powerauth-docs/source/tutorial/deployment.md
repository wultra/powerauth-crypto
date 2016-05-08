# Deploying PowerAuth 2.0 Server

This chapter explains how to deploy PowerAuth 2.0 Server.

PowerAuth 2.0 Server is a Java EE application (packaged as an executable WAR file) responsible for the PowerAuth 2.0 server-side cryptography implementation and data persistence. It exposes SOAP and RESTful API for the integrating applications (not end-user applications!), such as the internet banking or mobile banking API.

## Downloading PowerAuth 2.0 Server WAR

You can download the latest `powerauth-java-server.war` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

## Adding database connector on classpath

PowerAuth 2.0 Server supports any JPA 2.0 compatible database engine. In order for the database connectivity to work, you need to add appropriate DB client libraries on your classpath.

For example, when using MySQL with Tomcat, make sure to add `mysql-connector-java-${VERSION}.jar` to the `${CATALINA_HOME}/lib` folder (server restart will be required).

## Creating the database schema

In order for the PowerAuth 2.0 Server to work, you need to have a correct schema in the database. To create the correct database schema, execute these SQL scripts for your database engine (MySQL is used by default):

- [Default SQL Database Schema](https://github.com/lime-company/lime-security-powerauth/tree/master/powerauth-docs/sql)

## Connecting PowerAuth 2.0 Server to database

The default database connectivity parameters in `powerauth-java-server.war` are following (MySQL defaults):

```sh
spring.datasource.url=jdbc:mysql://localhost:3306/powerauth
spring.datasource.username=powerauth
spring.datasource.password=
spring.datasource.driver-class-name=com.mysql.jdbc.Driver
spring.jpa.hibernate.ddl-auto=none
```

These parameters are of course only for the testing purposes, they are not suitable for production environment. They should be overridden for your production environment using a standard [Spring database connectivity related properties](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html#boot-features-connect-to-production-database).

Note that some database engines (for example MySQL) let you specify the default schema as a part of a URL. Other engines (for example Oracle) do not allow this. In order to specify the correct schema, you need to use following property:

```sh
spring.jpa.properties.hibernate.default_schema=powerauth
```

## PowerAuth 2.0 Server configuration

_(optional)_ Optionally, you may set up following properties in order to configure your PowerAuth 2.0 Server instance:

```sh
powerauth.service.applicationName=powerauth
powerauth.service.applicationDisplayName=PowerAuth 2.0 Server
```

These properties are returned when calling the `getSystemStatus` method of the SOAP interface.

## Deploying PowerAuth 2.0 Server WAR file

You can deploy PowerAuth 2.0 Server WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-java-server/` (WSDL is then available on `http://localhost:8080/powerauth-java-server/soap/service.wsdl`).

To deploy PowerAuth 2.0 Server to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

## Deploying PowerAuth 2.0 Server outside the container

You can also execute PowerAuth 2.0 Server WAR file directly using the following command:

```bash
java -jar powerauth-java-server.war
```

_Note: You can overwrite the port using `-Dserver.port=8090` parameter to avoid port conflicts._

## Generating your first application

In order to initialize the database with an application, call PowerAuth 2.0 Server endpoint:

```bash
$ curl -s -H "Content-Type: application/json" -X POST -d '{ "requestObject": { "applicationName": "DEMO APPLICATION NAME" } }' http://localhost:8080/powerauth-java-server/rest/pa/application/create | json_pp
{
   "status" : "OK",
   "responseObject" : {
      "applicationId" : 1,
      "applicationName" : "DEMO APPLICATION NAME"
   }
}
```

This command will create:

- A new application instance named "DEMO APPLICATION NAME" with an `id = 1`.
- A default application version named "default" with associated `application_key` and `application_secret` values
- A new master key pair associated with the application.

To get the application details, you can copy the `applicationId` value from the previous response and call:

```bash
$ curl -s -H "Content-Type: application/json" -X POST -d '{ "requestObject": { "applicationId": 1 } }' http://localhost:8080/powerauth-java-server/rest/pa/application/detail | json_pp
{
   "status" : "OK",
   "responseObject" : {
      "masterPublicKey" : "BKOUTVjJKVB/AnRwq3tbqVkol6omI9DS6E/Yu3swh0l6MewONsjL01LA2/dxpgN5+6Ihy9cW1BpuYtdoFrxxlTA=",
      "applicationId" : 1,
      "versions" : [
         {
            "applicationVersionId" : 1,
            "applicationVersionName" : "default",
            "applicationKey" : "zinbZhRMTXP4UTY+QrjZsg==",
            "applicationSecret" : "tzE7Ps0Ia8G/pFM75rh6yA==",
            "supported" : true
         }
      ],
      "applicationName" : "DEMO APPLICATION NAME"
   }
}
```

You can then use these values in your PowerAuth 2.0 Client application. Read the tutorial to the reference client for more information:

- [Using PowerAuth 2.0 Reference Client](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/tutorial/console-client-app.md)
