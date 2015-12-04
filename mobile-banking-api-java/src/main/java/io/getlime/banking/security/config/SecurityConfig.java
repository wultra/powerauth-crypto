package io.getlime.banking.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private ApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http.authorizeRequests().antMatchers("/secured/**").fullyAuthenticated();
    	http.httpBasic().disable();
    	http.csrf().disable();
    	http.exceptionHandling().authenticationEntryPoint(apiAuthenticationEntryPoint);
    }

}
