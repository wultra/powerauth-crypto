package io.getlime.rest.api.security.entrypoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.getlime.rest.api.model.PowerAuthAPIResponse;

@Service
public class PowerAuthApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final Logger logger = LoggerFactory.getLogger(PowerAuthApiAuthenticationEntryPoint.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		try {
			logger.error("An authentication exception was thrown.", authException);

			PowerAuthAPIResponse<String> errorResponse = new PowerAuthAPIResponse<String>("ERROR", "Authentication failed");

			response.setContentType("application/json");
			response.setCharacterEncoding("UTF-8");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getOutputStream().println(new ObjectMapper().writeValueAsString(errorResponse));
			response.getOutputStream().flush();
		} catch (Exception e) {
			throw authException;
		}
	}

}
