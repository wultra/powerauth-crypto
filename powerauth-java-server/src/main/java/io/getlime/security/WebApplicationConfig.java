package io.getlime.security;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.mvc.annotation.ResponseStatusExceptionResolver;
import org.springframework.web.servlet.mvc.method.annotation.ExceptionHandlerExceptionResolver;

import io.getlime.security.service.controller.RESTResponseExceptionResolver;

@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

    @Override
    public void configureHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
        super.configureHandlerExceptionResolvers(exceptionResolvers);
        exceptionResolvers.add(new RESTResponseExceptionResolver());
        exceptionResolvers.add(new ExceptionHandlerExceptionResolver());
        exceptionResolvers.add(new ResponseStatusExceptionResolver());
    }

}
