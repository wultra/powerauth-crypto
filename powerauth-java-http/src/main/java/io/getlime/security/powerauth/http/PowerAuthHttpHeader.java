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

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Base class for processing any PowerAuth related HTTP headers.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public abstract class PowerAuthHttpHeader {

    /**
     * PowerAuth HTTP header prefix.
     */
    protected static final String POWERAUTH_PREFIX = "PowerAuth ";

    /**
     * Parse the PowerAuth authorization header and return map with values.
     * @param header HTTP header with PowerAuth authorization.
     * @return Map with parsed header values.
     */
    protected Map<String, String> parseHttpHeader(String header) {
        if (header == null) {
            return new HashMap<>(); // invalid map with empty values works better than null here
        }
        header = header.trim();
        if (!header.startsWith(POWERAUTH_PREFIX)) {
            return new HashMap<>(); // invalid map with empty values works better than null here
        }
        header = header.substring(POWERAUTH_PREFIX.length()).trim();

        // Parse the key / value pairs
        Map<String, String> result = new HashMap<>();
        Pattern p = Pattern.compile("(\\w+)=\"*((?<=\")[^\"]+(?=\")|([^\\s]+)),*\"*");
        Matcher m = p.matcher(header);
        while (m.find()) {
            result.put(m.group(1), m.group(2));
        }

        return result;
    }

    /**
     * Helper method to build key-value pair.
     * @param key Key.
     * @param value Value.
     * @return Key-value pair, constructed as: {key}="{value}".
     */
    protected String headerField(String key, String value) {
        return key + "=\"" + value + "\"";
    }

    // Abstract methods to be overridden by subclass headers

    /**
     * Return the instance of the current header type based on provided String value.
     *
     * @param headerValue Value of the HTTP header.
     * @return Instance of the header representation.
     */
    public abstract PowerAuthHttpHeader fromValue(String headerValue);

    /**
     * Return a string with the HTTP header value.
     * @return HTTP header value.
     */
    public abstract String buildHttpHeader();

}
