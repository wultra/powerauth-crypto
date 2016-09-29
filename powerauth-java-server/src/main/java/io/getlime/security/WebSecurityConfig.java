package io.getlime.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.service.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.service.controller.RESTResponseWrapper;
import io.getlime.security.service.integration.IntegrationUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class that implements configuration of the Spring Security for RESTful interface
 * of the PowerAuth 2.0 Server. This configuration is prepared in such a way that it
 * does not apply to the SOAP interface - only to REST.
 *
 * If a configuration "powerauth.service.restrictAccess" suggests that access should be
 * restricted, HTTP Basic Authentication is used for RESTful API endpoints. Username and
 * passwords can be set in the "pa_integration" table.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private IntegrationUserDetailsService userDetailsService;

    private PowerAuthServiceConfiguration configuration;

    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    @Autowired
    public void setUserDetailsService(IntegrationUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (configuration.getRestrictAccess()) {
            http
                    .authorizeRequests()
                    .antMatchers("/rest/**").authenticated()
                    .anyRequest().permitAll()
                    .and()
                    .httpBasic()
                    .authenticationEntryPoint(authenticationEntryPoint())
                    .and()
                    .csrf().disable();
        } else {
            http
                    .httpBasic().disable()
                    .csrf().disable();
        }
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            @Override public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                RESTResponseWrapper<String> errorResponse = new RESTResponseWrapper<>("ERROR", "Authentication failed");
                httpServletResponse.setContentType("application/json");
                httpServletResponse.setCharacterEncoding("UTF-8");
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.getOutputStream().println(new ObjectMapper().writeValueAsString(errorResponse));
                httpServletResponse.getOutputStream().flush();
            }
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return userDetailsService;
    }
}
