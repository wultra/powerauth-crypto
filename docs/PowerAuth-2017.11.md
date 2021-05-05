# PowerAuth 2017.11

### Back-End Applications

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Server | `powerauth-java-server.war` | 0.17.0 | Core back-end component for PowerAuth stack. |
| PowerAuth Admin | `powerauth-admin.war` | 0.17.0 | Administration console for PowerAuth Server. |
| PowerAuth Push Server | `powerauth-push-server.war` | 0.17.1 | Simple to deploy push server for APNS and FCM |

### Utilities

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Command Line Tool | `powerauth-java-cmd.jar` | 0.17.0 | Command line tool for integration testing |

### Mobile Libraries

| Platform | Package Name | Version | Description |
|---|---|---|---|
| IOS | `PowerAuth2` or `PowerAuth2-Debug` | 0.17.3 | A client library for IOS |
| watchOS | `PowerAuth2ForWatch` | 0.17.3 | A limited library for watchOS |
| IOS App Extensions | `PowerAuth2ForExtensions` | 0.17.3 | A limited library for IOS App Extensions |
| Android | `io.getlime.security.powerauth:powerauth-android-sdk` | 0.17.4 | A client library for Android |

### Back-End Integration Libraries

| Component | Library Name |  Version | Description |
|---|---|---|---|
| PowerAuth RESTful Model | `powerauth-restful-model.jar` | 0.17.1 | Model classes for request and response objects used in PowerAuth Standard RESTful API. |
| PowerAuth RESTful API Security for Spring | `powerauth-restful-security-spring.jar` | 0.17.1 | High-level integration libraries for RESTful API security, build for Spring MVC. |
| PowerAuth RESTful API Security for JAX-RS | `powerauth-restful-security-javaee.jar` | 0.17.1 | High-level integration libraries for RESTful API security, build for Java EE (JAX-RS). |
| PowerAuth SOAP Client for Spring WS | `powerauth-java-client-spring.jar` | 0.17.0 | SOAP service client for PowerAuth Server service, built using Spring WS. |
| PowerAuth SOAP Client for Axis2 | `powerauth-java-client-axis.jar` | 0.17.0 | SOAP service client for PowerAuth Server service, built using Axis2. |
| PowerAuth Push Server RESTful Model | `powerauth-push-model.jar` | 0.17.0 | Model classes for request and response objects used in PowerAuth Push Server. |
| PowerAuth Push Server RESTful Client | `powerauth-push-client.jar` | 0.17.0 | Client implementation that simplifies integration with PowerAuth Push Server service. |

### Technical Dependencies

| Component | Library Name | Version | Description |
|---|---|---|---|
| PowerAuth Cryptography | `powerauth-java-crypto.jar` | 0.17.0 | Core cryptography implementation of the PowerAuth protocol. |
| PowerAuth HTTP Utilities | `powerauth-java-http.jar` | 0.17.0 | Utilities used for binding PowerAuth cryptography to HTTP technology. |
| PowerAuth Cryptography Provider | `powerauth-java-prov.jar` | 0.17.0 | Abstraction on top of cryptography providers, so that Bouncy Castle can be switched to other implementation more easily. |
| PowerAuth Command-Line Tool Library | `powerauth-java-cmd-lib.jar` | 0.17.0 | Library used for implementation of the PowerAuth Command-Line Tool app, useful for unit testing. |
| PowerAuth RESTful Security Base Support | `powerauth-restful-security-base.jar` | 0.17.1 | Base classes for RESTful API security, shared between JAX-RS and Spring implementations. |
| Lime Java Networking Objects | `rest-model-base.jar` | 1.0.3 | Base classes for RESTful API networking, shared across all Lime back-end projects. |

## Known Issues When Updating From Older Versions

In case you are updating from older versions of PA stack, you might meet following issues:

- In case you are using custom activation, iOS and Android libraries before 0.17.0 will have issue with missing `encryption` attribute on network response during the activation process. You can workaround this issue by creating custom `MyEncryptedObjectResponse` that extends `ObjectResponse` and adds single field `encryption` with fixed value `nonpersonalized`, like so:

```java
public class MyEncryptedObjectResponse<T> extends ObjectResponse<T> {
    private final String encryption = "nonpersonalized";
    // ... getters and setters
}
```
