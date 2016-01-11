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
package io.getlime.rest.api.security.entrypoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.getlime.rest.api.model.PowerAuthAPIResponse;

@Service
public class PowerAuthApiAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		try {
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
