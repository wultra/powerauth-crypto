# Integrate PowerAuth 2.0 Server with a mobile banking server app

This tutorial shows the way mobile API developers integrate with PowerAuth 2.0 Server. There are several tasks mobile API service must perform in order for the PowerAuth to work:

- **Activation flow** - Mobile API must publish activation related endpoints for standard PowerAuth 2.0 API, so that client is able to perform PowerAuth key exchange. See "Standard RESTful API" chapter for details.
- **Vault unlocking** - Mobile API must publish secure vault unlocking endpoints for standard PowerAuth 2.0 API, so that client is able to unlock vault and retrieve original device private key.
- **Request signing** - Mobile API must call PowerAuth 2.0 Server for all endpoints that should validate the signature.

_Pro tip: You may speed up your development by reusing the example project (for example the model classes)._

## Prerequisites for the tutorial

- Running PowerAuth 2.0 Server with available SOAP interface.
- Knowledge of applications based on Spring Framework.
- Software: IDE - Spring Tool Suite, Java EE Application Server (Pivotal Server, Tomcat, ...)

## Creating a skeleton application

### Creating new project

Start Spring Tool Suite and select `File > New > Spring Starter Project`.

Name the project for example `mobile-banking-api-java` and configure your project (see image below). Click `Next`.

Select `Core > Security`, `Web > Web` and `Web > WS`. Click `Finish` and wait for Maven to do all the necessary setup work.

### Create a PowerAuth Model

Create classes `ActivationCreateRequest` and `ActivationCreateResponse` in a `model` sub-package.

```java
package io.getlime.banking.model;

public class ActivationCreateRequest {

	private String activationIdShort;
	private String activationNonce;
	private String cDevicePublicKey;
	private String clientName;

	public String getActivationIdShort() {
		return activationIdShort;
	}

	public void setActivationIdShort(String activationIdShort) {
		this.activationIdShort = activationIdShort;
	}

	public String getActivationNonce() {
		return activationNonce;
	}

	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}

	public String getcDevicePublicKey() {
		return cDevicePublicKey;
	}

	public void setcDevicePublicKey(String cDevicePublicKey) {
		this.cDevicePublicKey = cDevicePublicKey;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

}
```

```java
package io.getlime.banking.model;

public class ActivationCreateResponse {

	private String activationId;
	private String activationNonce;
	private String ephemeralPublicKey;
	private String cServerPublicKey;
	private String cServerPublicKeySignature;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

	public String getActivationNonce() {
		return activationNonce;
	}

	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}

	public String getEphemeralPublicKey() {
		return ephemeralPublicKey;
	}

	public void setEphemeralPublicKey(String ephemeralPublicKey) {
		this.ephemeralPublicKey = ephemeralPublicKey;
	}

	public String getcServerPublicKey() {
		return cServerPublicKey;
	}

	public void setcServerPublicKey(String cServerPublicKey) {
		this.cServerPublicKey = cServerPublicKey;
	}

	public String getcServerPublicKeySignature() {
		return cServerPublicKeySignature;
	}

	public void setcServerPublicKeySignature(String cServerPublicKeySignature) {
		this.cServerPublicKeySignature = cServerPublicKeySignature;
	}

}
```

Create classes `ActivationStatusRequest` and `ActivationStatusResponse` in a `model` sub-package.

```java
package io.getlime.banking.model;

public class ActivationStatusRequest {

	private String activationId;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

}
```

```java
package io.getlime.banking.model;

public class ActivationStatusResponse {

	private String activationId;
	private String cStatusBlob;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

	public String getcStatusBlob() {
		return cStatusBlob;
	}

	public void setcStatusBlob(String cStatusBlob) {
		this.cStatusBlob = cStatusBlob;
	}

}
```

Create classes `ActivationRemoveRequest` and `ActivationRemoveResponse` in a `model` sub-package.

```java
package io.getlime.banking.model;

public class ActivationRemoveRequest {

	private String activationId;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

}
```

```java
package io.getlime.banking.model;

public class ActivationRemoveResponse {

	private String activationId;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

}
```

Create classes `VaultUnlockRequest` and `VaultUnlockResponse` in a `model` sub-package.

```java
package io.getlime.banking.model;

public class VaultUnlockRequest {

	private String activationId;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

}
```

```java
package io.getlime.banking.model;

public class VaultUnlockResponse {

	private String activationId;
	private String cVaultEncryptionKey;

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

	public String getcVaultEncryptionKey() {
		return cVaultEncryptionKey;
	}

	public void setcVaultEncryptionKey(String cVaultEncryptionKey) {
		this.cVaultEncryptionKey = cVaultEncryptionKey;
	}

}
```

Create generic template classes `PowerAuthAPIRequest` and `PowerAuthAPIResponse` in a `model` sub-package.

```java
package io.getlime.banking.model;

public class PowerAuthAPIRequest<T> {

	private T requestObject;

	public T getRequestObject() {
		return requestObject;
	}

	public void setRequestObject(T requestObject) {
		this.requestObject = requestObject;
	}

}
```

```java
package io.getlime.banking.model;

public class PowerAuthAPIResponse<T> {

	private String status;
	private T responseObject;

  public PowerAuthAPIResponse(String status, T responseObject) {
		this.status = status;
		this.responseObject = responseObject;
	}

	public String getStatus() {
		return status;
	}

	public T getResponseObject() {
		return responseObject;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public void setResponseObject(T responseObject) {
		this.responseObject = responseObject;
	}

}
```

### Creating dummy endpoints

Create a class "ActivationController" in "controller" sub-package, annotate it as a controller and create dummy endpoints. This controller will implement all endpoints related to PowerAuth activation process.

```java
package io.getlime.banking.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.ActivationCreateRequest;
import io.getlime.banking.model.ActivationCreateResponse;
import io.getlime.banking.model.ActivationRemoveRequest;
import io.getlime.banking.model.ActivationRemoveResponse;
import io.getlime.banking.model.ActivationStatusRequest;
import io.getlime.banking.model.ActivationStatusResponse;
import io.getlime.banking.model.PowerAuthAPIRequest;
import io.getlime.banking.model.PowerAuthAPIResponse;

@Controller
@RequestMapping(value = "pa/activation")
public class ActivationController {

	@RequestMapping(value = "create", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationCreateResponse> createActivation(@RequestBody PowerAuthAPIRequest<ActivationCreateRequest> request) {
		return new PowerAuthAPIResponse<ActivationCreateResponse>("OK", null);
	}

	@RequestMapping(value = "status", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthAPIRequest<ActivationStatusRequest> request) {
		return new PowerAuthAPIResponse<ActivationStatusResponse>("OK", null);
	}

	@RequestMapping(value = "remove", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationRemoveResponse> removeActivation(@RequestBody PowerAuthAPIRequest<ActivationRemoveRequest> request) {
		return new PowerAuthAPIResponse<ActivationRemoveResponse>("OK", null);
	}

}
```

Create a class `SecureVaultController` in "controller" sub-package, annotate it as a controller and create dummy endpoints. This controller will be responsible for retrieving an encrypted vault unlock key.

```java
package io.getlime.banking.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIRequest;
import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.model.VaultUnlockRequest;
import io.getlime.banking.model.VaultUnlockResponse;

@Controller
@RequestMapping(value = "pa/vault")
public class SecureVaultController {

	@RequestMapping(value = "unlock", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<VaultUnlockResponse> unlockVault(@RequestBody PowerAuthAPIRequest<VaultUnlockRequest> request, @RequestHeader(name = "X-PowerAuth-Signature", required = true) {
		return new PowerAuthAPIResponse<VaultUnlockResponse>("OK", null);
	}

}
```

Create a class "AuthenticationController" in "controller" sub-package, annotate it as a controller and create dummy endpoints. This controller is used as an example controller for validation signature - it will have a single `/session/login` endpoint that establishes session on a successful PowerAuth signature. Therefore, we keep this endpoint simple - it accepts empty POST request with a `X-PowerAuth-Signature` header and returns a simple response.

```java
package io.getlime.banking.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIResponse;

@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

	@RequestMapping(value = "login", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<String> login(
      @RequestHeader(name = "X-PowerAuth-Signature", required = true) String signature) {
		return new PowerAuthAPIResponse<String>("OK", null);
	}

}
```

## Exception handling

// TODO:

## Generating PowerAuth 2.0 SOAP service client

Open `pom.xml` and add Maven plugin to generate classes from the web service descriptor (WSDL) in the `build` section. Make sure to set the proper path to WSDL file and proper package name.

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
        <!-- BEGIN: Generate sources from WSDL -->
        <plugin>
            <groupId>org.jvnet.jaxb2.maven2</groupId>
            <artifactId>maven-jaxb2-plugin</artifactId>
            <version>0.12.3</version>
            <executions>
                <execution>
                    <goals>
                        <goal>generate</goal>
                    </goals>
                </execution>
            </executions>
            <configuration>
                <schemaLanguage>WSDL</schemaLanguage>
                <generatePackage>io.getlime.powerauth.soap</generatePackage>
                <schemas>
                    <schema>
                        <url>http://localhost:8080/powerauth-java-server/powerauth/service.wsdl</url>
                    </schema>
                </schemas>
            </configuration>
        </plugin>
        <!-- END: Generate sources from WSDL -->
    </plugins>
</build>
```

After cleaning and building the project, you should see generated client sources under `target/generated/xjc` folder.

Implement a PowerAuth 2.0 SOAP service client - a `PowerAuthServiceClient` class in `soap.client` sub-package.

```java
package io.getlime.banking.soap.client;

import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import io.getlime.powerauth.soap.GetActivationStatusRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationRequest;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.powerauth.soap.VaultUnlockRequest;
import io.getlime.powerauth.soap.VaultUnlockResponse;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;

public class PowerAuthServiceClient extends WebServiceGatewaySupport {

	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
		return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

	public GetActivationStatusResponse activationStatus(GetActivationStatusRequest request) {
		return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
		return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

	public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
		return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
		return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}

}
```

Create a class `PowerAuthWebServiceConfiguration` in the top level package you use in order to allow auto-wiring of the web service client.

```java
package io.getlime.banking;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

import io.getlime.banking.soap.client.PowerAuthServiceClient;

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

## Configuring Spring Security

Create a new class `ApiAuthenticationEntryPoint` extending `AuthenticationEntryPoint` that represents your authentication entry point. Our implementation simply returns an error response whenever someone tries to visit our API unauthenticated (on classic web, this usually is a place to redirect user to the login page).

```java
package io.getlime.banking.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.getlime.banking.model.PowerAuthAPIResponse;

@Service
public class ApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final Logger logger = LoggerFactory.getLogger(ApiAuthenticationEntryPoint.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		try {
			logger.error("An authentication exception was thrown.", authException);

			PowerAuthAPIResponse<String> errorResponse = new PowerAuthAPIResponse<String>("ERROR",
					"Authentication failed");

			response.setContentType("application/json");
			response.setCharacterEncoding("UTF-8");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getOutputStream().println(new ObjectMapper().writeValueAsString(errorResponse));
			response.getOutputStream().flush();
		} catch (Exception e) {
			throw authException;
		}
	}

}
```

Create a security configuration class `SecurityConfig` extending `WebSecurityConfigurerAdapter` in a `security.config` sub-package. The configuration we will use:

	- disable default Basic HTTP authentication
	- disables CSRF (we don't need it for REST)
	- register your authentication entry point (if someone tries to visit our API without prior authentication, show error)
	- secures all REST endpoints with `/secured/` prefix

```java
package io.getlime.banking.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http.authorizeRequests().antMatchers("/secured/**").fullyAuthenticated();
    	http.httpBasic().disable();
    	http.csrf().disable();
    	http.exceptionHandling().authenticationEntryPoint(apiAuthenticationEntryPoint);
    }

}
```

## Implementing signature validation

Prepare a utility class `PowerAuthUtil` in `util` sub-package with a method for parsing an authorization header `X-PowerAuth-Signature` and for building the signature base string. To simplify the work, we will use the `Splitter` and `BaseEncoding` classes from `guava` by Google.

```java
package io.getlime.banking.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.springframework.security.crypto.codec.Hex;

import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;

public class PowerAuthUtil {

	private static final String POWERAUTH_PREFIX = "PowerAuth ";

	public static Map<String, String> parsePowerAuthSignatureHTTPHeader(String xPowerAuthSignatureHeader) {
		xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.trim();
		if (!xPowerAuthSignatureHeader.startsWith(POWERAUTH_PREFIX)) {
			return null;
		}
		xPowerAuthSignatureHeader.substring(POWERAUTH_PREFIX.length());
		Map<String, String> result = Splitter.onPattern("\\s(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
				.withKeyValueSeparator(Splitter.onPattern("=")).split(xPowerAuthSignatureHeader);
		return result;
	}

	public static String getSignatureBaseString(String httpMethod, String requestUri, String applicationSecret, String nonce, byte[] data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {

		String requestUriHash = "";
		if (requestUri != null) {
			MessageDigest shaUri = MessageDigest.getInstance("SHA-256");
			shaUri.update(requestUri.getBytes("UTF-8"));
			byte[] digest = shaUri.digest();
			requestUriHash = new String(Hex.encode(digest));
		}

		String dataBase64 = "";
		if (data != null) {
			dataBase64 = BaseEncoding.base64().encode(data);
		}

		return (httpMethod != null ? httpMethod.toUpperCase() : "GET")
				+ "&" + requestUriHash
				+ "&" + applicationSecret
				+ "&" + (nonce != null ? nonce : "")
				+ "&" + dataBase64;
	}

}
```

Then, implement the `ResettableStreamHttpServletRequest` helper class that will let you read the raw HTTP request body and reset the underlying `InputStream` (needed for Spring MVC @RequestBody annotation to work).

```java
package io.getlime.banking.security.filter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import com.google.common.primitives.Bytes;

public class ResettableStreamHttpServletRequest extends HttpServletRequestWrapper {

    private byte[] requestBody = new byte[0];
    private boolean bufferFilled = false;

    public ResettableStreamHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    public byte[] getRequestBody() throws IOException {
        if (bufferFilled) {
            return Arrays.copyOf(requestBody, requestBody.length);
        }

        InputStream inputStream = super.getInputStream();

        byte[] buffer = new byte[102400];

        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            requestBody = Bytes.concat(this.requestBody, Arrays.copyOfRange(buffer, 0, bytesRead));
        }

        bufferFilled = true;

        return requestBody;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CustomServletInputStream(getRequestBody());
    }

    private static class CustomServletInputStream extends ServletInputStream {

        private ByteArrayInputStream buffer;

        public CustomServletInputStream(byte[] contents) {
            this.buffer = new ByteArrayInputStream(contents);
        }

        @Override
        public int read() throws IOException {
            return buffer.read();
        }

		@Override
		public boolean isFinished() {
			return buffer.available() == 0;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener arg0) {
			 throw new RuntimeException("Not implemented");
		}

    }

}
```

Finally, implement a `PowerAuthRequestFilter` that reads the body and passes it as the request attribute.

```java
package io.getlime.banking.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

public class PowerAuthRequestFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		ResettableStreamHttpServletRequest resetableRequest = new ResettableStreamHttpServletRequest(request);
		byte[] body = resetableRequest.getRequestBody();
		resetableRequest.setAttribute("X-PowerAuth-Request-Body", new String(body, "UTF-8"));
		super.doFilter(resetableRequest, response, filterChain);
	}

}
```

Register the `PowerAuthRequestFilter` in `WebApplicationConfig` class (in the top level package).

```java
package io.getlime.banking;

import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import io.getlime.banking.security.filter.PowerAuthRequestFilter;

@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

    @Bean
    public FilterRegistrationBean powerAuthFilterRegistration () {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(new PowerAuthRequestFilter());
        registrationBean.setMatchAfter(true);
        registrationBean.addUrlPatterns("/secured/");
        return registrationBean;
    }

}
```

Implement `PowerAuthAuthenticationProvider` that carry out an actual signature validation using the SOAP service.

```java
package io.getlime.banking.security.provider;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

import io.getlime.banking.security.model.ApiAuthentication;
import io.getlime.banking.security.model.PowerAuthAuthentication;
import io.getlime.banking.soap.client.PowerAuthServiceClient;
import io.getlime.banking.util.PowerAuthUtil;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;

@Component
public class PowerAuthAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		PowerAuthAuthentication powerAuthAuthentication = (PowerAuthAuthentication) authentication;

		VerifySignatureRequest soapRequest = new VerifySignatureRequest();
		soapRequest.setActivationId(powerAuthAuthentication.getActivationId());
		soapRequest.setSignature(powerAuthAuthentication.getSignature());
		soapRequest.setSignatureType(powerAuthAuthentication.getSignatureType());
		try {
			String payload = PowerAuthUtil.getSignatureBaseString(powerAuthAuthentication.getHttpMethod(),
					powerAuthAuthentication.getRequestUri(), powerAuthAuthentication.getApplicationSecret(),
					powerAuthAuthentication.getNonce(), powerAuthAuthentication.getData());
			soapRequest.setData(payload);
		} catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
			return null;
		}

		VerifySignatureResponse soapResponse = powerAuthClient.verifySignature(soapRequest);

		if (soapResponse.isSignatureValid()) {
			ApiAuthentication apiAuthentication = new ApiAuthentication();
			apiAuthentication.setActivationId(soapResponse.getActivationId());
			apiAuthentication.setUserId(soapResponse.getUserId());
			apiAuthentication.setAuthenticated(true);
			return apiAuthentication;
		} else {
			return null;
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		if (authentication == PowerAuthAuthentication.class) {
			return true;
		}
		return false;
	}

	public ApiAuthentication checkRequestSignature(
			HttpServletRequest servletRequest,
			String requestUriIdentifier,
			String httpAuthorizationHeader) throws Exception {

		if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
			throw new Exception("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
		}

		byte[] requestBodyBytes = ((String)servletRequest.getAttribute("X-PowerAuth-Request-Body")).getBytes();

		Map<String, String> httpHeaderInfo = PowerAuthUtil.parsePowerAuthSignatureHTTPHeader(httpAuthorizationHeader);

		PowerAuthAuthentication powerAuthAuthentication = new PowerAuthAuthentication();
		powerAuthAuthentication.setActivationId(httpHeaderInfo.get("pa_activation_id"));
		powerAuthAuthentication.setApplicationSecret(httpHeaderInfo.get("pa_application_id")); // here should be the lookup!!!!
		powerAuthAuthentication.setNonce(httpHeaderInfo.get("nonce"));
		powerAuthAuthentication.setSignatureType(httpHeaderInfo.get("signature_type"));
		powerAuthAuthentication.setSignature(httpHeaderInfo.get("pa_signature"));
		powerAuthAuthentication.setHttpMethod(servletRequest.getMethod().toUpperCase());
		powerAuthAuthentication.setRequestUri(requestUriIdentifier);
		powerAuthAuthentication.setData(requestBodyBytes);

		ApiAuthentication auth = (ApiAuthentication) this.authenticate(powerAuthAuthentication);

		if (auth == null) {
			throw new Exception("POWER_AUTH_SIGNATURE_INVALID_VALUE");
		}

		return auth;
	}

}
```

From now on, you are able to use `checkRequestSignature` method to check if a signature for given request is matching.

## Implementing the activation endpoints

Now, it's the time to start calling PowerAuth SOAP service methods from within the RESTful controller methods.

Update the `ActivationController` class with code to call SOAP services - autowire the SOAP client and implement method calls (note: as you may notice, there is quite a lot of "manual labor" used on object conversion - in real world project, you should consider [Dozer](http://dozer.sourceforge.net/) or similar library to automate the conversion).

```java
package io.getlime.banking.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.ActivationCreateRequest;
import io.getlime.banking.model.ActivationCreateResponse;
import io.getlime.banking.model.ActivationRemoveRequest;
import io.getlime.banking.model.ActivationRemoveResponse;
import io.getlime.banking.model.ActivationStatusRequest;
import io.getlime.banking.model.ActivationStatusResponse;
import io.getlime.banking.model.PowerAuthAPIRequest;
import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.soap.client.PowerAuthServiceClient;
import io.getlime.powerauth.soap.GetActivationStatusRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationRequest;
import io.getlime.powerauth.soap.RemoveActivationResponse;

@Controller
@RequestMapping(value = "pa/activation")
public class ActivationController {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@RequestMapping(value = "create", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationCreateResponse> createActivation(@RequestBody PowerAuthAPIRequest<ActivationCreateRequest> request) {
		String activationIDShort = request.getRequestObject().getActivationIdShort();
		String activationNonce = request.getRequestObject().getActivationNonce();
		String cDevicePublicKey = request.getRequestObject().getcDevicePublicKey();
		String clientName = request.getRequestObject().getClientName();

		PrepareActivationRequest soapRequest = new PrepareActivationRequest();
		soapRequest.setActivationIdShort(activationIDShort);
		soapRequest.setActivationNonce(activationNonce);
		soapRequest.setCDevicePublicKey(cDevicePublicKey);
		soapRequest.setClientName(clientName);

		PrepareActivationResponse soapResponse = powerAuthClient.prepareActivation(soapRequest);

		ActivationCreateResponse response = new ActivationCreateResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setActivationNonce(soapResponse.getActivationNonce());
		response.setcServerPublicKey(soapResponse.getCServerPublicKey());
		response.setcServerPublicKeySignature(soapResponse.getCServerPublicKeySignature());
		response.setEphemeralPublicKey(soapResponse.getEphemeralPublicKey());

		return new PowerAuthAPIResponse<ActivationCreateResponse>("OK", response);
	}

	@RequestMapping(value = "status", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationStatusResponse> getActivationStatus(@RequestBody PowerAuthAPIRequest<ActivationStatusRequest> request) {
		String activationId = request.getRequestObject().getActivationId();

		GetActivationStatusRequest soapRequest = new GetActivationStatusRequest();
		soapRequest.setActivationId(activationId);

		GetActivationStatusResponse soapResponse = powerAuthClient.activationStatus(soapRequest);

		ActivationStatusResponse response = new ActivationStatusResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setcStatusBlob(soapResponse.getCStatusBlob());

		return new PowerAuthAPIResponse<ActivationStatusResponse>("OK", response);
	}

	@RequestMapping(value = "remove", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<ActivationRemoveResponse> removeActivation(@RequestBody PowerAuthAPIRequest<ActivationRemoveRequest> request) {
		String activationId = request.getRequestObject().getActivationId();

		RemoveActivationRequest soapRequest = new RemoveActivationRequest();
		soapRequest.setActivationId(activationId);

		RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(soapRequest);

		ActivationRemoveResponse response = new ActivationRemoveResponse();
		response.setActivationId(soapResponse.getActivationId());

		return new PowerAuthAPIResponse<ActivationRemoveResponse>("OK", response);
	}

}
```

## Implementing vault unlocking endpoints

Implement the SOAP calls in the vault unlock controller `SecureVaultController`, similarly as with the `ActivationController`. Note that in this case, we need to process the authentication header `X-PowerAuth-Signature` and also, the SOAP response should be handled more deeply in production - for example, you may check the `userId` with your database to verify that the correct person attempts to unlock the vault.

```java
package io.getlime.banking.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIRequest;
import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.model.VaultUnlockRequest;
import io.getlime.banking.model.VaultUnlockResponse;
import io.getlime.banking.soap.client.PowerAuthServiceClient;

@Controller
@RequestMapping(value = "pa/vault")
public class SecureVaultController {

	@Autowired
	private PowerAuthServiceClient powerAuthClient;

	@RequestMapping(value = "unlock", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<VaultUnlockResponse> unlockVault(
			@RequestBody PowerAuthAPIRequest<VaultUnlockRequest> request,
			@RequestHeader(name = "X-PowerAuth-Signature", required = true) String signature) {
		String activationId = request.getRequestObject().getActivationId();

		io.getlime.powerauth.soap.VaultUnlockRequest soapRequest = new io.getlime.powerauth.soap.VaultUnlockRequest();
		soapRequest.setActivationId(activationId);
		soapRequest.setSignature(null);
		soapRequest.setSignatureType(null);
		powerAuthClient.unlockVault(soapRequest);

		io.getlime.powerauth.soap.VaultUnlockResponse soapResponse = new io.getlime.powerauth.soap.VaultUnlockResponse();

		// ... validate the activation information here
		// if (!soapResponse.isSignatureValid()) {
		//    // return error
		// }

		VaultUnlockResponse response = new VaultUnlockResponse();
		response.setActivationId(soapResponse.getActivationId());
		response.setcVaultEncryptionKey(soapResponse.getCVaultEncryptionKey());

		return new PowerAuthAPIResponse<VaultUnlockResponse>("OK", response);
	}

}
```

## Implementing authentication endpoint

Go to `AuthenticationController` and perform following changes:

```java
package io.getlime.banking.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.model.PowerAuthAPIResponse;
import io.getlime.banking.security.model.ApiAuthentication;
import io.getlime.banking.security.provider.PowerAuthAuthenticationProvider;

@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

	@Autowired
	private PowerAuthAuthenticationProvider authenticationProvider;

	@RequestMapping(value = "login", method = RequestMethod.POST)
	public @ResponseBody PowerAuthAPIResponse<String> login(
			@RequestHeader(name = "X-PowerAuth-Signature", required = true) String signatureHeader,
			HttpServletRequest servletRequest) throws Exception {

		ApiAuthentication apiAuthentication = authenticationProvider.checkRequestSignature(
				servletRequest,
				"/session/login",
				signatureHeader
		);

		if (apiAuthentication != null && apiAuthentication.getUserId() != null) {
			SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
			return new PowerAuthAPIResponse<String>("OK", null);
		} else {
			throw new Exception("USER_NOT_AUTHENTICATED");
		}

	}

}
```

From now on, the `/session/login` endpoint verifies the PowerAuth signature and `SecurityContextHolder` authentication to new `ApiAuthentication` in case the signature matches the login request data. Note that `ApiAuthentication` class stores `userId` and `activationId` - you can access those later.

## Implementing secure endpoints

Let's add one more rather incomplete controller. We will call it `AccountsController`. This controller just shows how you can fetch accounts from your systems for a user who is logged in. You can simply fetch the `userId` from the `SecurityContextHolder`'s authentication object - see the `getUserId()` shortcut method - and then query your systems based on the `userId`.

```java
package io.getlime.banking.controller;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.security.model.ApiAuthentication;

@Controller
@RequestMapping(value = "/secured/accounts")
public class AccountController {

	private class Account {

	}

	private String getUserId() throws Exception {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication.getClass().equals(ApiAuthentication.class)) {
			return ((ApiAuthentication)authentication).getUserId();
		} else {
			throw new Exception("INVALID_AUTHENTICATION_OBJECT");
		}
	}

	@RequestMapping
	public @ResponseBody List<Account> accountList() throws Exception {
		String userId = getUserId();
		// fetch accounts from back-end systems for a given user
		return null;
	}

}
```
