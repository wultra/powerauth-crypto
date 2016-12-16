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
package io.getlime.rest.api.security.provider;

import com.google.common.io.BaseEncoding;
import io.getlime.rest.api.security.authentication.PowerAuthApiAuthenticationBase;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;
import io.getlime.rest.api.security.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.lib.enums.PowerAuthSignatureTypes;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class for PowerAuth 2.0 authentication provider.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public abstract class PowerAuthAuthenticationProviderBase {

    /**
     * Validate the signature from the PowerAuth 2.0 HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth 2.0 HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract PowerAuthApiAuthenticationBase validateRequestSignature(
            String httpMethod,
            byte[] httpBody,
            String requestUriIdentifier,
            String httpAuthorizationHeader,
            List<PowerAuthSignatureTypes> allowedSignatureTypes
    ) throws PowerAuthAuthenticationException;

    /**
     * The same as {{@link #validateRequestSignature(String, byte[], String, String, List)} but uses default accepted signature type (2FA or 3FA).
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Request body
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth 2.0 HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthenticationBase validateRequestSignature(String httpMethod, byte[] httpBody, String requestUriIdentifier, String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthSignatureTypes> defaultAllowedSignatureTypes = new ArrayList<>();
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateRequestSignature(httpMethod, httpBody, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedSignatureTypes);
    }

    /**
     * Validate a request signature, make sure only supported signature types are used.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth 2.0 HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of signatures.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthenticationBase validateRequestSignature(HttpServletRequest servletRequest, String requestUriIdentifier, String httpAuthorizationHeader, List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        String requestBodyString = ((String) servletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
        byte[] requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);
        return this.validateRequestSignature(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedSignatureTypes);
    }

    /**
     * The same as {{@link #validateRequestSignature(HttpServletRequest, String, String, List)} but uses default accepted signature type (2FA or 3FA).
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth 2.0 HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthenticationBase validateRequestSignature(HttpServletRequest servletRequest, String requestUriIdentifier, String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthSignatureTypes> defaultAllowedSignatureTypes = new ArrayList<>();
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        defaultAllowedSignatureTypes.add(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateRequestSignature(servletRequest, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedSignatureTypes);
    }

}
