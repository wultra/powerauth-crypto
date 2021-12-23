# PowerAuth 2021.11

## Migration guides

For updating to 2021.11, please follow these migration guides:

- [PowerAuth Server - Migration from version 1.1.0 to version 1.2.0](https://github.com/wultra/powerauth-server/blob/develop/docs/PowerAuth-Server-1.2.0.md)
- [PowerAuth Push Server - Migration from version 1.1.0 to version 1.2.0](https://github.com/wultra/powerauth-push-server/blob/develop/docs/PowerAuth-Push-Server-1.2.0.md)
- [PowerAuth Web Flow - Migration from version 1.1.0 to version 1.2.0](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Web-Flow-1.2.0.md)
- [PowerAuth Mobile SDK - Migration from version 1.5.0 to version 1.6.0](https://github.com/wultra/powerauth-mobile-sdk/blob/develop/docs/Migration-from-1.5-to-1.6.md)

## Components for version 2021.11

### Back-End Applications

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Server | `powerauth-java-server.war` | 1.2.0 | Core back-end component for PowerAuth stack. |
| PowerAuth Admin | `powerauth-admin.war` | 1.2.0 | Administration console for PowerAuth Server. |
| PowerAuth Push Server | `powerauth-push-server.war` | 1.2.0 | Simple to deploy push server for APNS and FCM. |
| PowerAuth Web Flow | `powerauth-webflow.war` | 1.2.0 | Central web authentication page. |
| PowerAuth Next Step | `powerauth-next-step.war` | 1.2.0 | Authorization server used for PowerAuth Web Flow component. |
| PowerAuth Data Adapter | `powerauth-data-adapter.war` | 1.2.0 | Customization component for PowerAuth Web Flow. |
| PowerAuth Tpp Engine | `powerauth-tpp-engine.war` | 1.2.0 | Third party provider registry and consent engine. |

### Utilities

| Component | Application Name | Version | Description |
|---|---|---|---|
| PowerAuth Command Line Tool | `powerauth-java-cmd.jar` | 1.2.0 | Command line tool for integration testing. |

### Mobile Libraries

| Platform | Package Name | Version | Description |
|---|---|---|---|
| iOS | `PowerAuth2` | 1.6.2 | A client library for iOS. |
| watchOS | `PowerAuth2ForWatch` | 1.6.2 | A limited library for watchOS. |
| iOS App Extensions | `PowerAuth2ForExtensions` | 1.6.2 | A limited library for iOS App Extensions. |
| Android | `com.wultra.android.powerauth:powerauth-sdk` | 1.6.2 | A client library for Android. |

### Back-End Integration Libraries

| Component | Library Name |  Version | Description |
|---|---|---|---|
| PowerAuth RESTful Model | `powerauth-restful-model.jar` | 1.2.0 | Model classes for request and response objects used in PowerAuth Standard RESTful API. |
| PowerAuth RESTful API Security for Spring | `powerauth-restful-security-spring.jar` | 1.2.0 | High-level integration libraries for RESTful API security, build for Spring MVC. |
| PowerAuth SOAP Client for Spring WS | `powerauth-java-client-spring.jar` | 1.2.0 | SOAP service client for PowerAuth Server service, built using Spring WS. |
| PowerAuth Push Server RESTful Model | `powerauth-push-model.jar` | 1.2.0 | Model classes for request and response objects used in PowerAuth Push Server. |
| PowerAuth Push Server RESTful Client | `powerauth-push-client.jar` | 1.2.0 | Client implementation that simplifies integration with PowerAuth Push Server service. |
| PowerAuth Data Adapter RESTful Model | `powerauth-data-adapter-model.jar` | 1.2.0 | Model classes for request and response objects used in PowerAuth Data Adapter component. |
| PowerAuth Data Adapter Client | `powerauth-data-adapter-client.jar` | 1.2.0 | Client implementation that simplifies integration with PowerAuth Data Adapter custom component. |
| PowerAuth Next Step RESTful Model | `powerauth-nextstep-model.jar` | 1.2.0 | Model classes for request and response objects used in PowerAuth Next Step service. |
| PowerAuth Next Step Client | `powerauth-nextstep-client.jar` | 1.2.0 | Client implementation that simplifies integration with PowerAuth Next Step service. |
| PowerAuth Mobile Token Model | `powerauth-mtoken-model.jar` | 1.2.0 | Model classes for request and response objects used in PowerAuth Mobile Token. |

### Technical Dependencies

| Component | Library Name | Version | Description |
|---|---|---|---|
| PowerAuth Cryptography | `powerauth-java-crypto.jar` | 1.2.0 | Core cryptography implementation of the PowerAuth protocol. |
| PowerAuth HTTP Utilities | `powerauth-java-http.jar` | 1.2.0 | Utilities used for binding PowerAuth cryptography to HTTP technology. |
| PowerAuth Command-Line Tool Library | `powerauth-java-cmd-lib.jar` | 1.2.0 | Library used for implementation of the PowerAuth Command-Line Tool app, useful for unit testing. |
| PowerAuth RESTful Security Spring | `powerauth-restful-security-spring.jar` | 1.2.0 | Spring integration library for RESTful API security. |
| Wultra Java Networking Objects | `rest-model-base.jar` | 1.4.0 | Base classes for RESTful API networking, shared across all Wultra back-end projects. |
| Wultra REST Client | `rest-client-base.jar` | 1.4.0 | Base RESTful client implementation, shared across all Wultra back-end projects. |

## Known Issues When Updating From Older Versions

_No known issues so far._