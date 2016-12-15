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
import com.google.common.io.ByteStreams;
import io.getlime.security.powerauth.lib.util.http.PowerAuthRequestCanonizationUtils;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;

/**
 * Request filter that intercepts the request body, forwards it to the controller 
 * as a request attribute named "X-PowerAuth-Request-Body" and resets the stream.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthRequestFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext)
            throws IOException {
        if (requestContext.getMethod().toUpperCase().equals("GET")) {
            // Parse the query parameters
            String queryString = requestContext.getUriInfo().getAbsolutePath().getQuery();

            // Get the canonized form
            String signatureBaseStringData = PowerAuthRequestCanonizationUtils.canonizeGetParameters(queryString);

            // Pass the signature base string as the request attribute
            if (signatureBaseStringData != null) {
                requestContext.setProperty(
                        PowerAuthRequestFilterConstant.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(signatureBaseStringData.getBytes("UTF-8"))
                );
            }

        } else { // ... handle POST, PUT, DELETE, ... method

            // Get the request body and pass it as the signature base string as the request attribute
            byte[] body = ByteStreams.toByteArray(requestContext.getEntityStream());
            if (body != null) {
                requestContext.setProperty(
                        PowerAuthRequestFilterConstant.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(body)
                );
            }
        }
    }

}
