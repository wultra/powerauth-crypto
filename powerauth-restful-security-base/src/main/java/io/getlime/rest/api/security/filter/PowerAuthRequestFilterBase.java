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

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Class representing for holding any static constants available to request filters.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthRequestFilterBase {

    /**
     * Constant for the request attribute name "X-PowerAuth-Request-Body".
     */
    public static final String POWERAUTH_SIGNATURE_BASE_STRING = "X-PowerAuth-Request-Body";

    public static ResettableStreamHttpServletRequest filterRequest(HttpServletRequest httpRequest) throws IOException {
        ResettableStreamHttpServletRequest resettableRequest = new ResettableStreamHttpServletRequest(httpRequest);
        if (httpRequest.getMethod().toUpperCase().equals("GET")) {
            // Parse the query parameters
            String queryString = httpRequest.getQueryString();

            if (queryString != null && queryString.length() > 0) {

                // Get the canonized form
                String signatureBaseStringData = PowerAuthRequestCanonizationUtils.canonizeGetParameters(queryString);

                // Pass the signature base string as the request attribute
                if (signatureBaseStringData != null) {
                    resettableRequest.setAttribute(
                            PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING,
                            BaseEncoding.base64().encode(signatureBaseStringData.getBytes("UTF-8"))
                    );
                }

            }

        } else { // ... handle POST, PUT, DELETE, ... method

            // Get the request body and pass it as the signature base string as the request attribute
            byte[] body = resettableRequest.getRequestBody();
            if (body != null) {
                resettableRequest.setAttribute(
                        PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(body)
                );
            }
        }
        return resettableRequest;
    }

}
