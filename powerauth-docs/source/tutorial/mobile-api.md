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
        registrationBean.addUrlPatterns("/secured/");
        return registrationBean;
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
            @RequestHeader(name = "X-PowerAuth-Signature", required = true) String signatureHeader,
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

}```
