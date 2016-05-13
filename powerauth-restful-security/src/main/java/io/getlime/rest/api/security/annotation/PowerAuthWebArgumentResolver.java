package io.getlime.rest.api.security.annotation;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;

@Component
public class PowerAuthWebArgumentResolver implements HandlerMethodArgumentResolver {

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return parameter.getParameterType().equals(PowerAuthApiAuthentication.class);
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
		HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
		PowerAuthApiAuthentication authentication = (PowerAuthApiAuthentication) request.getAttribute(PowerAuth.AUTHENTICATION_OBJECT);
		System.out.println("DEBUG>>> 2 >>> >>> " + authentication.toString());
		return authentication;
	}

}
