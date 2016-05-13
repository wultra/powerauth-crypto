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
  <version>0.10.0</version>
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

### Register a PowerAuth components

As a part of the PowerAuth integration setup, you need to register following components by registering appropriate `@Beans` and by adding these components to the Spring life-cycle in your `WebMvcConfigurerAdapter`:

```java
@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

  @Bean
  public PowerAuthWebArgumentResolver powerAuthWebArgumentResolver() {
    return new PowerAuthWebArgumentResolver();
  }

  @Bean
  public PowerAuthInterceptor powerAuthInterceptor() {
    return new PowerAuthInterceptor();
  }

  @Bean
  public FilterRegistrationBean powerAuthFilterRegistration () {
    FilterRegistrationBean registrationBean = new FilterRegistrationBean();
    registrationBean.setFilter(new PowerAuthRequestFilter());
    registrationBean.setMatchAfter(true);
    registrationBean.addUrlPatterns("/secured/*");
    return registrationBean;
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(powerAuthInterceptor());
    super.addInterceptors(registry);
  }

  @Override
  public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
    argumentResolvers.add(powerAuthWebArgumentResolver());
    super.addArgumentResolvers(argumentResolvers);
  }

}
```

`PowerAuthWebArgumentResolver` bean is responsible for auto-injecting PowerAuth 2.0 authentication objects into the controller handler methods (see example at "Verify signatures" chapter). You need to add it to argument resolver list.

`PowerAuthInterceptor` bean is responsible for the `@PowerAuth` annotation handling (see example at "Verify signatures" chapter). You need to add it to the interceptor registry.

And finally, the `FilterRegistrationBean` (with the `PowerAuthRequestFilter` filter) is a technical component that passes the HTTP request body as an attribute of `HttpServletRequest`, so that it can be used for signature validation.

### Register a PowerAuth application registry

_(optional)_

PowerAuth uses the concept of `application ID` and `application secret`. While `applicationId` attribute is transmitted with requests in `X-PowerAuth-Authorization` header, `applicationSecret` is shared implicitly between client and server and is a part of the actual signature value. Applications are a first class citizen in PowerAuth protocol. Intermediate application, however, may influence which applications are accepted by implementing following configuration.

```java
@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {

  @Override
  public boolean isAllowedApplicationKey(String applicationKey) {
    return true; // suggested default implementation
  }

  @Override
  public Map<String, Object> statusServiceCustomObject() {
    return null; // suggested default implementation
  }

}
```

### Set up Spring Security

_(optional)_

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

This sample `@Controller` implementation illustrates how to use `@PowerAuth` annotation to verify that the request signature matches what is expected - in this case, to establish an authenticated session. In case the authentication is not successful, the `PowerAuthAuthenticationException` is automatically raised that is handled alongside other application exceptions, for example via `@ControllerAdvice`.

_Note: Controllers that establish a session must not be on a context that is protected by Spring Security (for example "/secured/", in our example), otherwise context could never be reached and session will never be established._

```java
@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

  @RequestMapping(value = "login", method = RequestMethod.POST)
  @PowerAuth(resourceId = "/session/login")
  public @ResponseBody PowerAuthAPIResponse<String> login(PowerAuthApiAuthentication apiAuthentication) {

      String userId = apiAuthentication.getUserId(); // use userId if needed ...
      SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
      return new PowerAuthAPIResponse<String>("OK", null);

  }

}
```

In case you need a more low-level access to the signature verification, you can verify the signature manually using the `PowerAuthAuthenticationProvider` like this:

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

    PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature(
      "POST",
      "Any data".getBytes("UTF-8"),
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
