/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.http;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Helper class simplifying working with HTTP request body in context of PowerAuth protocol.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthHttpBody {

    /**
     * Prepare signature base string ("data to be signed") using request parameters.
     * @param httpMethod HTTP Method (for example "GET", "POST", "PUT", "DELETE", ...)
     * @param requestUri Request URI identifier (for example "/secure/payment", or "SEC_PAYM" - structure of URI ID is lose, but the first approach is suggested)
     * @param nonce Random 16B nonce value.
     * @param data Request data.
     * @return PowerAuth signature base string.
     */
    public static String getSignatureBaseString(String httpMethod, String requestUri, byte[] nonce, byte[] data) {

        String requestUriHash = "";
        if (requestUri != null) {
            byte[] bytes = requestUri.getBytes(StandardCharsets.UTF_8);
            requestUriHash = Base64.getEncoder().encodeToString(bytes);
        }

        String dataBase64 = "";
        if (data != null) {
            dataBase64 = Base64.getEncoder().encodeToString(data);
        }

        String nonceBase64 = "";
        if (nonce != null) {
            nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        }

        return (httpMethod != null ? httpMethod.toUpperCase() : "GET")
                + "&" + requestUriHash
                + "&" + nonceBase64
                + "&" + dataBase64;
    }

}
