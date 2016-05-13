package io.getlime.rest.api.security.annotation;

import java.util.ArrayList;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.lib.util.http.PowerAuthHttpHeader;

@Component
public class PowerAuthInterceptor extends HandlerInterceptorAdapter {

	@Autowired
	private PowerAuthAuthenticationProvider authenticationProvider;

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

		HandlerMethod handlerMethod = (HandlerMethod) handler;
		PowerAuth powerAuthAnnotation = handlerMethod.getMethodAnnotation(PowerAuth.class);

		if (powerAuthAnnotation != null) {

			PowerAuthApiAuthentication authentication = this.authenticationProvider.validateRequestSignature(
					request, 
					powerAuthAnnotation.resourceId(), 
					request.getHeader(PowerAuthHttpHeader.HEADER_NAME), 
					new ArrayList<>(Arrays.asList(powerAuthAnnotation.signatureType()))
			);

			if (authentication == null) { // ... authentication failed
				throw new PowerAuthAuthenticationException();
			} else { // ... pass authentication object 
				request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
			}

		}

		return super.preHandle(request, response, handler);
	}

}
