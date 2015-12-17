# Integrate PowerAuth 2.0 Server with an Internet banking server app

This tutorial shows the way internet banking (or other "master front-end application") developers integrate with PowerAuth 2.0 Server. There are several tasks a master front-end application must usually perform:

- **Activation initialization** - Application must be able to generate a new activation data, in order to allow PowerAuth 2.0 Client to start the activation flow.
- **Activation commit** - As soon as the PowerAuth 2.0 Client application finishes the key exchange and user authorizes the exchange in the master front-end application (for example by rewriting an SMS code or code from a HW token), master fromt-end application must commit the activation to make it active and useable for request signing.
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

### Using the PowerAuthServiceClient in your sources

In order to use a `PowerAuthServiceClient` instance, you can easily `@autowire` it in your class, for example in your Spring MVC `@Controller`, like this:

```java
@Controller
@RequestMapping(value = "/ib/settings")
public class AuthenticationController {

    @Autowired
    private PowerAuthServiceClient powerAuthServiceClient;

    // ... Controller code

}
```

### Obtaining the new activation data

To generate a new activation data for a given user ID, call the `initActivation` method of the `PowerAuthServiceClient` instance.

### Committing activation

To commit an activation with given `activationId`, call the `commitActivation` method of the `PowerAuthServiceClient` instance.

```java
```

### Getting the list and detail for the given activation

To get the list of activations for a given user ID, call the `getActivationListForUser` method of the `PowerAuthServiceClient` instance.

```java
// your actual user identifier
String userId = "1234";

// Short way to read the activations
List<Activations> activations = powerAuthServiceClient.getActivationListForUser(userId);

// ... or using the original SOAP request-response notion ...
GetActivationListForUserRequest request = new GetActivationListForUserRequest();
request.setUserId(userId);
GetActivationListForUserResponse response = powerAuthServiceClient.getActivationListForUser(request);
List<Activations> activations = response.getActivations();
```

You can also get a detail of an individual activation based on `activationId` by calling the `getActivationStatus` method of the `PowerAuthServiceClient`

```java
// your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to read the activation status
GetActivationStatusResponse response = powerAuthServiceClient.getActivationStatus(activationId);

// ... or using the original SOAP request-response notion ...
GetActivationStatusRequest request = new GetActivationStatusRequest();
request.setActivationId(activationId)
GetActivationStatusResponse response = powerAuthServiceClient.getActivationStatus(request);
```

### Blocking, unblocking and removing activation

To block an activation with given `activationId`, call the `blockActivation` method of the `PowerAuthServiceClient` instance.

```java
// your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to block the activation
BlockActivationResponse response = powerAuthServiceClient.blockActivation(activationId);

// ... or using the original SOAP request-response notion ...
BlockActivationRequest request = new BlockActivationRequest();
request.setActivationId(activationId)
BlockActivationResponse response = powerAuthServiceClient.blockActivation(request);
```

To unblock an activation with given `activationId`, call the `unblockActivation` method of the `PowerAuthServiceClient` instance.

```java
// your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to unblock the activation
UnblockActivationResponse response = powerAuthServiceClient.unblockActivation(activationId);

// ... or using the original SOAP request-response notion ...
UnblockActivationRequest request = new UnblockActivationRequest();
request.setActivationId(activationId)
UnblockActivationResponse response = powerAuthServiceClient.unblockActivation(request);
```

To remove an activation with given `activationId`, call the `removeActivation` method of the `PowerAuthServiceClient` instance. Note that unlike with the PowerAuth 2.0 Standard RESTful API (usually called by PowerAuth 2.0 Client), this call does not require PowerAuth 2.0 authorization signature.

```java
// your actual activation identifier
String activationId = "509d4c95-ef0d-4338-ab3a-64e730921fd1";

// Short way to remove the activation
RemoveActivationResponse response = powerAuthServiceClient.removeActivation(activationId);

// ... or using the original SOAP request-response notion ...
RemoveActivationRequest request = new RemoveActivationRequest();
request.setActivationId(activationId)
RemoveActivationResponse response = powerAuthServiceClient.removeActivation(request);
```
