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
package io.getlime.security.powerauth.rest.api.base.authentication;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public interface PowerAuthAuthentication {

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    String getActivationId();

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    void setActivationId(String activationId);

    /**
     * Get application key.
     * @return Application key.
     */
    String getApplicationKey();

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    void setApplicationKey(String applicationKey);

    /**
     * Get signature.
     * @return Signature.
     */
    String getSignature();

    /**
     * Set signature.
     * @param signature Signature.
     */
    void setSignature(String signature);

    /**
     * Get signature type.
     * @return Signature type.
     */
    String getSignatureType();

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    void setSignatureType(String signatureType);

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    String getRequestUri();

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    void setRequestUri(String requestUri);

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    String getHttpMethod();

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    void setHttpMethod(String httpMethod);

    /**
     * Get nonce.
     * @return Nonce.
     */
    byte[] getNonce();

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    void setNonce(byte[] nonce);

    /**
     * Get request data.
     * @return Request data.
     */
    byte[] getData();

    /**
     * Set request data.
     * @param data Request data.
     */
    void setData(byte[] data);

}
