package io.getlime.rest.api;

import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import io.getlime.rest.api.security.filter.PowerAuthRequestFilter;

@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

	@Bean
	public FilterRegistrationBean powerAuthFilterRegistration() {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean();
		registrationBean.setFilter(new PowerAuthRequestFilter());
		registrationBean.setMatchAfter(true);
		registrationBean.addUrlPatterns("/secured/");
		return registrationBean;
	}

}
