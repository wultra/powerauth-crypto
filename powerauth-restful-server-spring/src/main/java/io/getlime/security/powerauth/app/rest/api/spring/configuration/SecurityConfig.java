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
package io.getlime.security.powerauth.app.rest.api.spring.configuration;

import io.getlime.security.powerauth.rest.api.spring.entrypoint.PowerAuthApiAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Spring Security default configuration maps the default "entry-point" to all
 * end-points on /secured/** context path, disables HTTP basic and disables CSRF.
 *
 * @author Petr Dvorak
 *
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private PowerAuthApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

    @Autowired
    public void setApiAuthenticationEntryPoint(PowerAuthApiAuthenticationEntryPoint apiAuthenticationEntryPoint) {
        this.apiAuthenticationEntryPoint = apiAuthenticationEntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.csrf().disable();
        http.authorizeRequests().antMatchers("/secured/**").fullyAuthenticated();
        http.exceptionHandling().authenticationEntryPoint(apiAuthenticationEntryPoint);
    }

}
