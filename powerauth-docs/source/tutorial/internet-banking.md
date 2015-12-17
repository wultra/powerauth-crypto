# Integrate PowerAuth 2.0 Server with an Internet banking server app

This tutorial shows the way internet banking (or other "master front-end application") developers integrate with PowerAuth 2.0 Server. There are several tasks a master front-end application must usually perform:

- **Activation initialization** - Application must be able to generate a new activation data, in order to allow PowerAuth 2.0 Client to start the activation flow.
- **Activation overview tasks** - Application must be able to lookup and display activation records for given user in order to show what activations does the given user have and to allow performing the activation status management tasks.
- **Activation status management tasks** - Application must be able to manage states of the given activation - to block, unblock or remove a given activation.

## Prerequisites for the tutorial

- Running PowerAuth 2.0 Server with available SOAP interface.
- Knowledge of applications based on Spring Framework.
- Software: IDE - Spring Tool Suite, Java EE Application Server (Pivotal Server, Tomcat, ...)

## Integration manual

### Add a Maven dependency

To add a PowerAuth support in your application, add Maven dependency for PowerAuth RESTful Client module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-java-client</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### Configure PowerAuth SOAP Service

In order to connect to the correct PowerAuth 2.0 Server, you need add following configuration:

```java
@Configuration
public class PowerAuthWebServiceConfiguration {

	@Bean
	public Jaxb2Marshaller marshaller() {
		Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
		marshaller.setContextPath("io.getlime.powerauth.soap");
		return marshaller;
	}

	@Bean
	public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
		PowerAuthServiceClient client = new PowerAuthServiceClient();
		client.setDefaultUri("http://localhost:8080/powerauth-java-server/powerauth");
		client.setMarshaller(marshaller);
		client.setUnmarshaller(marshaller);
		return client;
	}

}
```

### Getting the new activation data

### Getting the list and detail for the given activation

### Blocking, unblocking and removing activation
