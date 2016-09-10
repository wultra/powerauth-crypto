/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.rest.api.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 6495166873663643144L;

    private String activationId;
    private String applicationKey;
    private String signature;
    private String signatureType;
    private String requestUri;
    private String httpMethod;
    private byte[] nonce;
    private byte[] data;

    /**
     * Default constructor.
     */
    public PowerAuthAuthentication() {
        super(null);
    }

    @Override
    public Object getCredentials() {
        return signature;
    }

    @Override
    public Object getPrincipal() {
        return activationId;
    }

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get signature.
     * @return Signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Set signature.
     * @param signature Signature.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Get signature type.
     * @return Signature type.
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get request data.
     * @return Request data.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Set request data.
     * @param data Request data.
     */
    public void setData(byte[] data) {
        this.data = data;
    }

}
