# PowerAuth 2018.06

## Migration guides

For updating to 2018.06, please follow these migration guides:

- [PowerAuth Server - Migration from version 0.18.0 to version 0.19.0](https://github.com/wultra/powerauth-server/blob/develop/docs/PowerAuth-Server-0.19.0.md)
- [PowerAuth Web Flow - Migration from version 0.19.0 to version 0.20.0](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Web-Flow-0.20.0.md)
- [PowerAuth Mobile SDK - Release Notes - 0.20.0](https://github.com/wultra/powerauth-mobile-sdk/releases/tag/0.20.0)

## Components for version 2018.06

### Back-End Applications

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Server | `powerauth-java-server.war` | 0.19.0 | Core back-end component for PowerAuth stack. |
| PowerAuth Admin | `powerauth-admin.war` | 0.19.0 | Administration console for PowerAuth Server. |
| PowerAuth Push Server | `powerauth-push-server.war` | 0.19.0 | Simple to deploy push server for APNS and FCM. |
| PowerAuth Web Flow | `powerauth-webflow.war` | 0.20.0 | Central web authentication page. |
| PowerAuth Next Step | `powerauth-next-step.war` | 0.20.0 | Simple authorization server used for PowerAuth Web Flow component. |
| PowerAuth Data Adapter | `powerauth-data-adapter.war` | 0.20.0 | Customization component for PowerAuth Web Flow. |

### Utilities

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Command Line Tool | `powerauth-java-cmd.jar` | 0.19.0 | Command line tool for integration testing |

### Mobile Libraries

| Platform | Package Name | Version | Description |
|---|---|---|---|
| iOS | `PowerAuth2` | 0.20.3 | A client library for iOS |
| watchOS | `PowerAuth2ForWatch` | 0.20.3 | A limited library for watchOS |
| iOS App Extensions | `PowerAuth2ForExtensions` | 0.20.3 | A limited library for iOS App Extensions |
| Android | `io.getlime.security.powerauth:powerauth-android-sdk` | 0.20.3 | A client library for Android |

### Back-End Integration Libraries

| Component | Library Name |  Version | Description |
|---|---|---|---|
| PowerAuth RESTful Model | `powerauth-restful-model.jar` | 0.19.0 | Model classes for request and response objects used in PowerAuth Standard RESTful API. |
| PowerAuth RESTful API Security for Spring | `powerauth-restful-security-spring.jar` | 0.19.0 | High-level integration libraries for RESTful API security, build for Spring MVC. |
| PowerAuth RESTful API Security for JAX-RS | `powerauth-restful-security-javaee.jar` | 0.19.0 | High-level integration libraries for RESTful API security, build for Java EE (JAX-RS). |
| PowerAuth SOAP Client for Spring WS | `powerauth-java-client-spring.jar` | 0.19.0 | SOAP service client for PowerAuth Server service, built using Spring WS. |
| PowerAuth SOAP Client for Axis2 | `powerauth-java-client-axis.jar` | 0.19.0 | SOAP service client for PowerAuth Server service, built using Axis2. |
| PowerAuth Push Server RESTful Model | `powerauth-push-model.jar` | 0.19.0 | Model classes for request and response objects used in PowerAuth Push Server. |
| PowerAuth Push Server RESTful Client | `powerauth-push-client.jar` | 0.19.0 | Client implementation that simplifies integration with PowerAuth Push Server service. |
| PowerAuth Data Adapter RESTful Model | `powerauth-data-adapter-model.jar` | 0.20.0 | Model classes for request and response objects used in PowerAuth Data Adapter component. |
| PowerAuth Data Adapter Client | `powerauth-data-adapter-client.jar` | 0.20.0 | Client implementation that simplifies integration with PowerAuth Data Adapter custom component. |
| PowerAuth Next Step RESTful Model | `powerauth-nextstep-model.jar` | 0.20.0 | Model classes for request and response objects used in PowerAuth Next Step service. |
| PowerAuth Next Step Client | `powerauth-nextstep-client.jar` | 0.20.0 | Client implementation that simplifies integration with PowerAuth Next Step service. |
| PowerAuth Mobile Token Model | `powerauth-mtoken-model.jar` | 0.20.0 | Model classes for request and response objects used in PowerAuth Mobile Token. |

### Technical Dependencies

| Component | Library Name | Version | Description |
|---|---|---|---|
| PowerAuth Cryptography | `powerauth-java-crypto.jar` | 0.19.0 | Core cryptography implementation of the PowerAuth protocol. |
| PowerAuth HTTP Utilities | `powerauth-java-http.jar` | 0.19.0 | Utilities used for binding PowerAuth cryptography to HTTP technology. |
| PowerAuth Cryptography Provider | `powerauth-java-prov.jar` | 0.19.0 | Abstraction on top of cryptography providers, so that Bouncy Castle can be switched to other implementation more easily. |
| PowerAuth Command-Line Tool Library | `powerauth-java-cmd-lib.jar` | 0.19.0 | Library used for implementation of the PowerAuth Command-Line Tool app, useful for unit testing. |
| PowerAuth RESTful Security Base Support | `powerauth-restful-security-base.jar` | 0.19.0 | Base classes for RESTful API security, shared between JAX-RS and Spring implementations. |
| Lime Java Networking Objects | `rest-model-base.jar` | 1.1.0 | Base classes for RESTful API networking, shared across all Lime back-end projects. |

## Known Issues When Updating From Older Versions

_No known issues so far._