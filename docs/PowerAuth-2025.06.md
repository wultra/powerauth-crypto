# PowerAuth 2025.06


## Migration guides

For updating to 2025.06, please follow these migration guides:

- [PowerAuth Server - Migration from version 1.9.0 to version 1.10.0](https://github.com/wultra/powerauth-server/blob/develop/docs/PowerAuth-Server-1.10.0.md)
- [PowerAuth Push Server - Migration from version 1.9.0 to version 1.10.0](https://github.com/wultra/powerauth-push-server/blob/develop/docs/PowerAuth-Push-Server-1.10.0.md)
- [PowerAuth Web Flow - Migration from version 1.9.0 to version 1.10.0](https://github.com/wultra/powerauth-webflow/blob/develop/docs/Web-Flow-1.10.0.md)


## Components for version 2025.06


### Back-End Applications

| Component              | Application Name             | Version | Description                                                 |
|------------------------|------------------------------|---------|-------------------------------------------------------------|
| PowerAuth Server       | `powerauth-java-server.war`  | 1.10.0  | Core back-end component for PowerAuth stack.                |
| PowerAuth Admin        | `powerauth-admin.war`        | 1.10.0  | Administration console for PowerAuth Server.                |
| PowerAuth Push Server  | `powerauth-push-server.war`  | 1.10.0  | Simple to deploy push server for APNS and FCM.              |
| Enrollment Server      | `enrollment-server.war`      | 1.10.0  | Enrollment server for PowerAuth.                            |
| PowerAuth Web Flow     | `powerauth-webflow.war`      | 1.10.0  | Central web authentication page.                            |
| PowerAuth Next Step    | `powerauth-next-step.war`    | 1.10.0  | Authorization server used for PowerAuth Web Flow component. |
| PowerAuth Data Adapter | `powerauth-data-adapter.war` | 1.10.0  | Customization component for PowerAuth Web Flow.             |
| PowerAuth Tpp Engine   | `powerauth-tpp-engine.war`   | 1.10.0  | Third party provider registry and consent engine.           |


### Utilities

| Component                   | Application Name            | Version | Description                                                                       |
|-----------------------------|-----------------------------|---------|-----------------------------------------------------------------------------------|
| PowerAuth Command Line Tool | `powerauth-java-cmd.jar`    | 1.10.0  | Command line tool for integration testing.                                        |
| User Data Store             | `user-data-store.war`       | 1.4.0   | Server component which stores clients personal data securely.                     |
| Liveness Check Proxy        | `liveness-check-proxy.war`  | 1.1.0   | Server component which is used for biometric liveness check.                      |
| Mobile Utility Server       | `mobile-utility-server.war` | 1.10.0  | Server component for dynamic SSL pinning, text localization, and other utilities. |
| SSL Pinning Tool            | `ssl-pinning-tool.jar`      | 1.10.0  | A command line utility used to sign SSL certificates for dynamic SSL pinning.     |


### Mobile Libraries

| Platform           | Package Name                                      | Version | Description                                 |
|--------------------|---------------------------------------------------|---------|---------------------------------------------|
| iOS                | `PowerAuth2`                                      | 1.9.4   | A client library for iOS.                   |
| watchOS            | `PowerAuth2ForWatch`                              | 1.9.4   | A limited library for watchOS.              |
| iOS App Extensions | `PowerAuth2ForExtensions`                         | 1.9.4   | A limited library for iOS App Extensions.   |
| Android            | `com.wultra.android.powerauth:powerauth-sdk`      | 1.9.4   | A client library for Android.               |
| React Native       | `react-native-powerauth-mobile-sdk`               | 2.5.3   | React Native wrapper library for PowerAuth. | 
| mToken SDK iOS     | `WultraMobileTokenSDK`                            | 1.11.1  | Mobile Token SDK for the iOS platform.      |
| mToken SDK Android | `com.wultra.android.mtokensdk:mtoken-sdk-android` | 1.11.1  | Mobile Token SDK for the Android platform.  |


### Back-End Integration Libraries

| Component                                 | Library Name                            | Version | Description                                                                                     |
|-------------------------------------------|-----------------------------------------|---------|-------------------------------------------------------------------------------------------------|
| PowerAuth RESTful Model                   | `powerauth-restful-model.jar`           | 1.10.0  | Model classes for request and response objects used in PowerAuth Standard RESTful API.          |
| PowerAuth RESTful API Security for Spring | `powerauth-restful-security-spring.jar` | 1.10.0  | High-level integration libraries for RESTful API security, build for Spring MVC.                |
| PowerAuth REST Client for Spring          | `powerauth-rest-client-spring.jar`      | 1.10.0  | REST service client for PowerAuth Server service.                                               |
| PowerAuth Push Server RESTful Model       | `powerauth-push-model.jar`              | 1.10.0  | Model classes for request and response objects used in PowerAuth Push Server.                   |
| PowerAuth Push Server RESTful Client      | `powerauth-push-client.jar`             | 1.10.0  | Client implementation that simplifies integration with PowerAuth Push Server service.           |
| PowerAuth Data Adapter RESTful Model      | `powerauth-data-adapter-model.jar`      | 1.10.0  | Model classes for request and response objects used in PowerAuth Data Adapter component.        |
| PowerAuth Data Adapter Client             | `powerauth-data-adapter-client.jar`     | 1.10.0  | Client implementation that simplifies integration with PowerAuth Data Adapter custom component. |
| PowerAuth Next Step RESTful Model         | `powerauth-nextstep-model.jar`          | 1.10.0  | Model classes for request and response objects used in PowerAuth Next Step service.             |
| PowerAuth Next Step Client                | `powerauth-nextstep-client.jar`         | 1.10.0  | Client implementation that simplifies integration with PowerAuth Next Step service.             |
| PowerAuth Mobile Token Model              | `mtoken-model.jar`                      | 1.10.0  | Model classes for request and response objects used in PowerAuth Mobile Token.                  |


### Technical Dependencies

| Component                           | Library Name                 | Version | Description                                                                                      |
|-------------------------------------|------------------------------|---------|--------------------------------------------------------------------------------------------------|
| PowerAuth Cryptography              | `powerauth-java-crypto.jar`  | 1.10.0  | Core cryptography implementation of the PowerAuth protocol.                                      |
| PowerAuth HTTP Utilities            | `powerauth-java-http.jar`    | 1.10.0  | Utilities used for binding PowerAuth cryptography to HTTP technology.                            |
| PowerAuth Command-Line Tool Library | `powerauth-java-cmd-lib.jar` | 1.10.0  | Library used for implementation of the PowerAuth Command-Line Tool app, useful for unit testing. |
| Wultra Java Networking Objects      | `rest-model-base.jar`        | 1.12.0  | Base classes for RESTful API networking, shared across all Wultra back-end projects.             |
| Wultra REST Client                  | `rest-client-base.jar`       | 1.12.0  | Base RESTful client implementation, shared across all Wultra back-end projects.                  |
| Wultra Auditing Library             | `audit-base.jar`             | 1.12.0  | Base auditing library, shared across all Wultra back-end projects.                               |


## Known Issues When Updating From Older Versions

_No known issues so far._
