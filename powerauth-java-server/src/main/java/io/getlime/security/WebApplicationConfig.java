package io.getlime.security;

import java.util.List;

import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.web.ErrorPageFilter;
import org.springframework.context.annotation.Bean;
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
	
    @Bean
    /**
     * Custom error page filter to disable default spring error handling.
     * @return ErrorPageFilter instance
     */
    public ErrorPageFilter errorPageFilter() {
        return new ErrorPageFilter();
    }

    @Bean
    /**
     * Register a custom error page filter to disable default spring error handling.
     * @param filter ErrorPageFilter to be used.
     * @return Filter registration bean.
     */
    public FilterRegistrationBean disableSpringBootErrorFilter(ErrorPageFilter filter) {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(filter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }
    
}
