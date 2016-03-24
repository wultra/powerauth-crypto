/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.rest.api.configuration;

import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import io.getlime.rest.api.security.filter.PowerAuthRequestFilter;

/**
 * Default implementation of WebMvcConfigurerAdapter, maps PowerAuthRequestFilter instance
 * (that passes HTTP request body to the request as an attribute, so that it's available
 * in the controller) to /pa/signature/validate demo end-point.
 * 
 * @author Petr Dvorak
 *
 */
@Configuration
public class WebApplicationConfig extends WebMvcConfigurerAdapter {

	/**
	 * Register a new PowerAuthRequestFilter and map it to /pa/signature/validate end-point.
	 * @return PowerAuthRequestFilter instance.
	 */
	@Bean
	public FilterRegistrationBean powerAuthFilterRegistration() {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean();
		registrationBean.setFilter(new PowerAuthRequestFilter());
		registrationBean.setMatchAfter(true);
		registrationBean.addUrlPatterns("/pa/signature/validate");
		return registrationBean;
	}

}
