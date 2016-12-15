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
package io.getlime.rest.api.security.filter;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.lib.util.http.PowerAuthRequestCanonizationUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Request filter that intercepts the request body, forwards it to the controller 
 * as a request attribute named "X-PowerAuth-Request-Body" and resets the stream.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        ResettableStreamHttpServletRequest resettableRequest = new ResettableStreamHttpServletRequest(request);
        if (request.getMethod().toUpperCase().equals("GET")) {
            // Parse the query parameters
            String queryString = request.getQueryString();

            // Get the canonized form
            String signatureBaseStringData = PowerAuthRequestCanonizationUtils.canonizeGetParameters(queryString);

            // Pass the signature base string as the request attribute
            if (signatureBaseStringData != null) {
                resettableRequest.setAttribute(
                        PowerAuthRequestFilterConstant.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(signatureBaseStringData.getBytes("UTF-8"))
                );
            }

        } else { // ... handle POST, PUT, DELETE, ... method

            // Get the request body and pass it as the signature base string as the request attribute
            byte[] body = resettableRequest.getRequestBody();
            if (body != null) {
                resettableRequest.setAttribute(
                        PowerAuthRequestFilterConstant.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(body)
                );
            }
        }
        super.doFilter(resettableRequest, response, filterChain);
    }

}
