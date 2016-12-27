/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.app.server;

import io.getlime.security.powerauth.app.server.service.configuration.PowerAuthServiceConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.security.wss4j.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j.callback.SpringSecurityPasswordValidationCallbackHandler;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;

import java.util.List;

/**
 * PowerAuth 2.0 Server default web service configuration. Configures both basic endpoint information
 * (service, port, xsd) and security (WS-Security, with UsernameToken authentication) in case it is
 * enabled in application configuration ("powerauth.service.restrictAccess").
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@EnableWs
@Configuration
public class WebServiceConfig extends WsConfigurerAdapter {

    private UserDetailsService userDetailsService;

    private PowerAuthServiceConfiguration configuration;

    /**
     * Setter for configuration injection.
     * @param configuration Configuration.
     */
    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Constructor that accepts an instance of UserDetailsServicce for autowiring.
     * @param userDetailsService UserDetailsService instance.
     */
    @Autowired
    public WebServiceConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Callback handler that uses autowired UserDetailsService to accommodate authentication.
     * @return Password validation callback handler.
     */
    @Bean
    public SpringSecurityPasswordValidationCallbackHandler securityCallbackHandler() {
        SpringSecurityPasswordValidationCallbackHandler callbackHandler = new SpringSecurityPasswordValidationCallbackHandler();
        callbackHandler.setUserDetailsService(userDetailsService);
        return callbackHandler;
    }

    /**
     * Default implementation of WS-Security interceptor that uses "UsernameToken" authentication.
     * @return Default WS-Security interceptor.
     */
    @Bean
    public Wss4jSecurityInterceptor securityInterceptor(){
        Wss4jSecurityInterceptor securityInterceptor = new Wss4jSecurityInterceptor();
        securityInterceptor.setValidationActions("UsernameToken");
        securityInterceptor.setValidationCallbackHandler(securityCallbackHandler());
        return securityInterceptor;
    }

    /**
     * Specify security interceptor in case restricted access is enabled in configuration.
     * @param interceptors Interceptor list, to be enriched with custom interceptor.
     */
    @Override
    public void addInterceptors(List<EndpointInterceptor> interceptors) {
        // If a restricted access is required, add a security interceptor...
        if (configuration.getRestrictAccess()) {
            interceptors.add(securityInterceptor());
        }
        super.addInterceptors(interceptors);
    }

    /**
     * Map the SOAP interface to ${CONTEXT_PATH}/soap path.
     *
     * @param applicationContext Application context.
     * @return New servlet registration with correct context.
     */
    @Bean
    public ServletRegistrationBean messageDispatcherServlet(ApplicationContext applicationContext) {
        MessageDispatcherServlet servlet = new MessageDispatcherServlet();
        servlet.setApplicationContext(applicationContext);
        servlet.setTransformWsdlLocations(true);
        return new ServletRegistrationBean(servlet, "/soap/*");
    }

    /**
     * Specify SOAP service parameters from WSDL file. Map service WSDP to
     * ${CONTEXT_PATH}/soap/service.wsdl address.
     *
     * @param powerAuthSchema XSD schema with PowerAuth service objects.
     * @return WSDL definition.
     */
    @Bean(name = "service")
    public DefaultWsdl11Definition defaultWsdl11Definition(XsdSchema powerAuthSchema) {
        DefaultWsdl11Definition wsdl11Definition = new DefaultWsdl11Definition();
        wsdl11Definition.setPortTypeName("PowerAuthPort");
        wsdl11Definition.setLocationUri("/soap");
        wsdl11Definition.setTargetNamespace("http://getlime.io/security/powerauth");
        wsdl11Definition.setSchema(powerAuthSchema);
        return wsdl11Definition;
    }

    /**
     * Return PowerAuth 2.0 Server service XSD schema.
     *
     * @return Correct XSD schema.
     */
    @Bean
    public XsdSchema countriesSchema() {
        return new SimpleXsdSchema(new ClassPathResource("xsd/PowerAuth-2.0.xsd"));
    }

}
