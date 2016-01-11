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
package io.getlime.rest.api.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.io.BaseEncoding;

public class PowerAuthRequestFilter extends OncePerRequestFilter {
	
	public static final String HTTP_BODY = "X-PowerAuth-Request-Body";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		ResettableStreamHttpServletRequest resetableRequest = new ResettableStreamHttpServletRequest(request);
		byte[] body = resetableRequest.getRequestBody();
		if (body != null) {
			resetableRequest.setAttribute(HTTP_BODY, BaseEncoding.base64().encode(body));
		}
		super.doFilter(resetableRequest, response, filterChain);
	}

}
