# Additional Activation OTP

<!-- begin box info -->
This part of the documentation describes in detail how usage of additional activation OTP changes the activation process. So, before you start, you should be familiar with actors and processes defined for the [regular activation](Activation.md).
<!-- end -->

The purpose of additional activation OTP is to help with the user authentication, or with the activation confirmation. The additional OTP can be used either in the early stages of the activation or later when the activation is created and waits for the confirmation in the PENDING_COMMIT state.

We will describe each situation in detail in the separate chapters:

1. [Additional user authentication](#additional-user-authentication)
   - [Regular activation with OTP](#regular-activation-with-otp)
   - [Custom activation with OTP](#custom-activation-with-otp)
2. [Activation confirmation](#activation-confirmation)
   - [Confirm regular activation with OTP](#confirm-regular-activation-with-otp)
   - [Confirm custom activation with OTP](#confirm-custom-activation-with-otp)
   - [Confirm activation recovery with OTP](#confirm-activation-recovery-with-otp)

## Additional User Authentication

In this common scenario, it's expected that the PowerAuth activation is not yet created so that the additional activation OTP can be used in the time of the activation creation as additional user authentication.

### Regular Activation With OTP

1. User is authenticated in Master Front-End Application and initiates the activation creation process:

   1. Master Front-End Application generates random activation OTP.
   1. Master Front-End Application then asks PowerAuth server to create an activation, with using this OTP ([`initActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-initactivation) method, OTP validation set to ON_KEY_EXCHANGE).
   1. Master Front-End Application then displays QR code, containing an activation code.
   1. At the same time, Master Front-End Application initiates the delivery of activation OTP. It's recommended to deliver such code via a dedicated out-of-band channel, for example, via SMS.

1. In the mobile application:

   1. The user scans QR code or retypes the activation code manually.
   1. The user waits for OTP delivery via the out-of-band channel.
   1. The user retypes OTP to the mobile application.
   1. Mobile application then initializes the activation, using activation code and OTP.

1. Intermediate Server Application receives activation with activation code and OTP:

   1. The activation code and OTP are verified by the PowerAuth server in the [`prepareActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-prepareactivation) method.
   1. If the method call succeeds, the activation is set to the ACTIVE state. There's no need to wait for the confirmation.
   1. In case that received OTP is wrong, the user has a limited number of retry attempts. The activation will be removed after too many failures.

1. The mobile application receives the response from the server and completes the activation on the mobile side.


### Custom Activation With OTP

There are multiple ways how to implement custom activation with an additional authentication OTP so that we will discuss only one particular case. What they have all common and what you need to know is that OTP is, in this case, not verified by PowerAuth Server. It's more practical to validate it before the actual activation creation.

1. Let's say that the user is authenticated in Master Front-End Application (with username and password) and initiates the activation creation process:

   1. Master Front-End Application generates random activation OTP and keeps it temporarily in the database.
   1. At the same time, Master Front-End Application initiates the delivery of activation OTP. It's recommended to deliver such code via a dedicated out-of-band channel, for example, via SMS.
   1. Master Front-End Application instructs the user to start the mobile application and type the username, password, and OTP to the mobile app.

1. In the mobile application:

   1. The user enters username and password.
   1. The user waits for OTP delivery via the out-of-band channel.
   1. The user retypes OTP.
   1. Mobile application then initializes the custom activation with provided username, password, and OTP.

1. Intermediate Server Application receives a custom activation request, with username, password, and OTP:

   1. The username, password, and OTP is verified by the Intermediate Server Application.
   1. If everything's right, then Intermediate Server Application creates activation by calling [`createActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-createactivation). The activation state can be set to ACTIVE.

1. The mobile application receives the response from the server and completes the activation on the mobile side.

## Activation Confirmation

In this common scenario, an additional activation OTP helps with the final activation confirmation, so the OTP is required in the later stages of the activation process (during the commit). In this case, it doesn't matter how the activation process was initiated. You can confirm regular, custom and also recovery activations with the OTP.

### Confirm Regular Activation With OTP

1. User is authenticated in Master Front-End Application and initiates the activation creation process:

   1. Master Front-End Application generates random activation OTP and keeps it temporarily in the database.
   1. Master Front-End Application then asks PowerAuth server to create an activation, with using this OTP ([`initActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-initactivation) method, OTP validation set to ON_COMMIT).
   1. Master Front-End Application then displays QR code, containing an activation code.

1. In the mobile application:

   1. The user scans QR code or retypes the activation code manually.
   1. Mobile application then initializes the activation, using activation code.

1. Intermediate Server Application receives a regular activation request, with activation code:

   1. The activation code is verified by the PowerAuth server in the [`prepareActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-prepareactivation) method.
   1. If the method call succeeds, the activation is set to the PENDING_COMMIT state.
   1. At the same time, Intermediate Server Application initiates the delivery of activation OTP. It's recommended to deliver such code via a dedicated out-of-band channel, for example, via SMS.

1. The mobile application receives the response from the server and completes the keys-exchange on the mobile side.

Now it depends whether the user has to retype OTP back to the Master Front-End Application, or the mobile application.

1. For the first case, the implementation is straightforward. Once the user retypes OTP back to Master Front-End Application, the activation can be completed on PowerAuth Server by calling [`commitActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-commitactivation) method. In case the commit fails, the number of commit attempts is limited to the [`MAX_FAILED_ATTEMPTS`](Computing-and-Validating-Signatures.md#constants-and-variables).

2. In case the OTP is retyped in the mobile application, the additional RESTful endpoint has to be implemented on the Intermediate Server Application. We recommend to use our [ECIES encryption](End-To-End-Encryption.md) to protect such endpoint. In case the commit fails, the number of commit attempts is limited to the [`MAX_FAILED_ATTEMPTS`](Computing-and-Validating-Signatures.md#constants-and-variables).

For both cases, it's recommended to generate a new OTP in case that delivery failed (e.g. user did not receive SMS). You can use [`updateActivationOtp`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-updateactivationotp) method to set a new OTP to the PowerAuth Server.

You can also slightly alter this whole sequence, and generate the first OTP later, in the step 3. In this case, you have to use [`updateActivationOtp`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-updateactivationotp) in the same step, to set the OTP.

### Confirm Custom Activation With OTP

There are multiple ways how to implement custom activation and confirm it with an additional authentication OTP so that we will discuss only one particular case. In this scenario, we don't involve the Master Front-End Application in the process, but we expect that the user has already issued some valid credentials to the system.

1. In the mobile application:

   1. The user enters username and password.
   1. Mobile application then initializes the custom activation with provided username and password.

1. Intermediate Server Application receives a custom activation request, with username and password:

   1. The username and password is verified by the Intermediate Server Application.
   1. If everything's right, then Intermediate Server Application creates activation by calling [`createActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-createactivation). The activation must be set to the PENDING_COMMIT state.
   1. Intermediate Server Application generates random activation OTP and update the activation record, by calling [`updateActivationOtp`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-updateactivationotp) method.
   1. At the same time, Intermediate Server Application initiates the delivery of activation OTP.

1. Back in the mobile application:

   1. The mobile application receives the response from the server and completes the key exchange on the mobile side.
   1. The user waits for OTP delivery via the out-of-band channel.
   1. The user retypes OTP.
   1. Mobile application then commits the activation with OTP, by calling a custom RESTful endpoint, protected with our [ECIES encryption](End-To-End-Encryption.md) scheme.

1. Intermediate Server Application then receives the commit request:

   1. Decrypts OTP from the request
   1. Commits the activation by calling PowerAuth Server's [`commitActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-commitactivation) method.

After the response from the commit is received on the mobile side, the application can check whether the activation's state is ACTIVE.

### Confirm Activation Recovery With OTP

The confirmation of activation recovery is very similar to custom activation confirmation.

1. In the mobile application:

   1. The user enters recovery code and PUK.
   1. Mobile application then initializes the recovery activation with provided code and PUK.

1. Intermediate Server Application receives a recovery activation request:

   1. The recovery code and PUK is verified by the PowerAuth Server, by calling [`recoveryCodeActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-recoverycodeactivation).
   1. Intermediate Server Application generates random activation OTP and update the activation record, by calling [`updateActivationOtp`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-updateactivationotp) method.
   1. At the same time, Intermediate Server Application initiates the delivery of activation OTP.

1. Back in the mobile application:

   1. The mobile application receives the response from the server and completes the keys-exchange on the mobile side.
   1. The user waits for OTP delivery via the out-of-band channel.
   1. The user retypes OTP.
   1. Mobile application then commits the activation with OTP, by calling a custom RESTful endpoint, protected with our [ECIES encryption](End-To-End-Encryption.md) scheme.

1. Intermediate Server Application then receives the commit request:

   1. Decrypts OTP from the request.
   1. Commits the activation by calling PowerAuth Server's [`commitActivation`](https://github.com/wultra/powerauth-server/blob/develop/docs/WebServices-Methods.md#method-commitactivation) method.

After the response from the commit is received on the mobile side, the application can check whether the activation's state is ACTIVE.
