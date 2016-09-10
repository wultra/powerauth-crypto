/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security;

import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition;
import org.springframework.xml.xsd.SimpleXsdSchema;
import org.springframework.xml.xsd.XsdSchema;

/**
 * PowerAuth 2.0 Server default web service configuration.
 *
 * @author Petr Dvorak
 */
@EnableWs
@Configuration
public class WebServiceConfig extends WsConfigurerAdapter {

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
