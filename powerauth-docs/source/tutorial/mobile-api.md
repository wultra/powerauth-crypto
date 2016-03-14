# Integrate PowerAuth 2.0 Server with a mobile banking server app

This tutorial shows the way mobile API developers integrate with PowerAuth 2.0 Server. There are several tasks mobile API service must perform in order for the PowerAuth to work:

- **Activation flow** - Mobile API must publish activation related endpoints for standard PowerAuth 2.0 API, so that client is able to perform PowerAuth key exchange. See "Standard RESTful API" chapter for details.
- **Vault unlocking** - Mobile API must publish secure vault unlocking endpoints for standard PowerAuth 2.0 API, so that client is able to unlock vault and retrieve original device private key.
- **Request signing** - Mobile API must call PowerAuth 2.0 Server for all endpoints that should validate the signature.

## Prerequisites for the tutorial

- Running PowerAuth 2.0 Server with available SOAP interface.
- Knowledge of applications based on Spring Framework.
- Software: IDE - Spring Tool Suite, Java EE Application Server (Pivotal Server, Tomcat, ...)

## Integration manual

### Create a new project

Start Spring Tool Suite and select `File > New > Spring Starter Project`.

Name the project for example `mobile-banking-api-java` and configure your project (see image below). Click `Next`.

Select `Core > Security`, `Web > Web` and `Web > WS`. Click `Finish` and wait for Maven to do all the necessary setup work.

### Add a Maven dependency

To add PowerAuth support in your RESTful API, add Maven dependency for PowerAuth RESTful Security module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-restful-security</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

To read about PowerAuth project Maven modules, visit [Maven modules](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/source/maven-modules.md) documentation.

### Configure PowerAuth SOAP Service

In order to connect to the correct PowerAuth 2.0 Server, you need add following configuration:

```java
@Configuration
@ComponentScan(basePackages = {"io.getlime.rest"})
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
		client.setDefaultUri("http://localhost:8080/powerauth-java-server/soap");
		client.setMarshaller(marshaller);
		client.setUnmarshaller(marshaller);
		return client;
	}

}
```

### Register a PowerAuth reqest filter

In order to pass the original request body as an attribute of `HttpServletRequest`, you need to register following filter:

```java
@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

    @Bean
    public FilterRegistrationBean powerAuthFilterRegistration () {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(new PowerAuthRequestFilter());
        registrationBean.setMatchAfter(true);
        registrationBean.addUrlPatterns("/secured/*");
        return registrationBean;
    }

}
```

### Register a PowerAuth application registry

PowerAuth uses the concept of `application ID` and `application secret`. While `applicationId` attribute is transmitted with requests in `X-PowerAuth-Authorization` header, `applicationSecret` is shared implicitly between client and server and is a part of the actual signature value. As a result, `PowerAuthAuthenticationProvider` component must be able to lookup `applicationSecret` based on `applicationId`. To achieve this, you need to register an instance of `PowerAuthApplicationConfiguration`, for example like this:

```java
@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {

	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";

	@Override
	public String getApplicationSecretForApplicationId(String applicationId) {
		if (applicationId.equals(ApplicationConfiguration.expectedApplicationId)) {
			return ApplicationConfiguration.expectedApplicationSecret;
		}
		return null;
	}

}
```

### Set up Spring Security

Create a security configuration class `SecurityConfig` extending `WebSecurityConfigurerAdapter`. The configuration we will use:

- disable default Basic HTTP authentication
- disables CSRF (we don't need it for REST)
- register your authentication entry point (if someone tries to visit our API without prior authentication, show error)
- secures all REST endpoints with `/secured/` prefix


```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PowerAuthApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http.authorizeRequests().antMatchers("/secured/**").fullyAuthenticated();
    	http.httpBasic().disable();
    	http.csrf().disable();
    	http.exceptionHandling().authenticationEntryPoint(apiAuthenticationEntryPoint);
    }

}
```

### Verify signatures

This sample `@Controller` implementation illustrates how to use `PowerAuthAuthenticationProvider` to verify that the request signature matches what is expected - in this case, to achieve the authenticated session. In case the authentication is not successful, controller raises the `PowerAuthAuthenticationException` that is handled alongside other application exceptions, for example via `@ControllerAdvice`.

```java
@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

    @Autowired
    private PowerAuthAuthenticationProvider authenticationProvider;

    @RequestMapping(value = "login", method = RequestMethod.POST)
    public @ResponseBody PowerAuthAPIResponse<String> login(
            @RequestHeader(value = "X-PowerAuth-Authorization", required = true) String signatureHeader,
            HttpServletRequest servletRequest) throws Exception {

        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.checkRequestSignature(
                servletRequest,
                "/session/login",
                signatureHeader
        );

        if (apiAuthentication != null && apiAuthentication.getUserId() != null) {
            SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
            return new PowerAuthAPIResponse<String>("OK", null);
        } else {
            throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
        }

    }

}
```
