# Deploying PowerAuth 2.0 Admin

This chapter explains how to deploy PowerAuth 2.0 Admin.

PowerAuth 2.0 Admin is a Java EE application (packaged as an executable WAR file) that you can use to work with the PowerAuth 2.0 Server services in a more visual way. Namely, PowerAuth 2.0 Admin provides a front-end user interface for following user scenarios:

- Creating a new application
- Creating a new application version
- Overview of applications
- Overview of application versions
- Unsupporting / Supporting an application version
- Creating a new activation for given user ID
- Committing an unfinished activation with given ID
- List of activations for given user ID
- Blocking / Unblocking activation with given ID
- Removing activation with given ID
- Listing last signatures computed using given activation

The PowerAuth 2.0 Admin may serve as a simple example application for the Internet banking integrators, since in essence, it performs the very same tasks.

**__Important note: Since PowerAuth 2.0 Admin is a very simple application with direct access to the PowerAuth 2.0 Server SOAP services, it must not be under any circumstances published publicly and must be constrained to the in-house closed infrastructure.__**

## Downloading PowerAuth 2.0 Admin

You can download the latest `powerauth-admin.war` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

## Configuring PowerAuth 2.0 Admin

The default implementation of a PowerAuth 2.0 Admin has only one proprietary configuration parameter `powerauth.service.url` that configures the SOAP endpoint location of a PowerAuth 2.0 Server. The default value for this property points to `localhost`:

```bash
powerauth.service.url=http://localhost:8080/powerauth-java-server/soap
```

## Deploying PowerAuth 2.0 Admin

You can deploy PowerAuth 2.0 Admin into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-admin/`.

To deploy PowerAuth 2.0 Admin to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

**__Important note: Since PowerAuth 2.0 Admin is a very simple application with direct access to the PowerAuth 2.0 Server SOAP services, it must not be under any circumstances published publicly and must be constrained to the in-house closed infrastructure.__**

## Deploying PowerAuth 2.0 Admin outside the container

You can also execute WAR file directly using the following command:

```bash
java -jar powerauth-admin.war
```

_Note: You can overwrite the port using `-Dserver.port=8090` parameter to avoid port conflicts._

**__Important note: Since PowerAuth 2.0 Admin is a very simple application with direct access to the PowerAuth 2.0 Server SOAP services, it must not be under any circumstances published publicly and must be constrained to the in-house closed infrastructure.__**
