package io.getlime.rest.api.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

public class PowerAuthRequestFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		ResettableStreamHttpServletRequest resetableRequest = new ResettableStreamHttpServletRequest(request);
		byte[] body = resetableRequest.getRequestBody();
		resetableRequest.setAttribute("X-PowerAuth-Request-Body", new String(body, "UTF-8"));
		super.doFilter(resetableRequest, response, filterChain);
	}

}
