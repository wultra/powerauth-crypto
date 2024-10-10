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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Canonization utilities for PowerAuth requests.
 */
public class PowerAuthRequestCanonizationUtils {

    /**
     * Utility variable, used for the purpose of GET query attribute sorting (query attribute key).
     */
    private static final String KEY = "key";

    /**
     * Utility variable, used for the purpose of GET query attribute sorting (query attribute value).
     */
    private static final String VAL = "val";

    /**
     * Take the GET request query string (for example, "param1=key1&amp;param2=key2") and convert it to the
     * canonized form by sorting the key value pairs primarily by keys and by values in case the keys are
     * equal.
     *
     * @param queryString The original get query string, obtained for example by 'request.getQueryString();'.
     * @return Canonized query string.
     */
    public static String canonizeGetParameters(String queryString) {
        if (queryString == null) {
            return "";
        }
        List<Map<String, String>> items = new ArrayList<>();
        String[] keyValuePairs = queryString.split("&"); // ... get the key value pairs
        for (String keyValue : keyValuePairs) {
            String[] tmp = keyValue.split("=", 2);
            if (tmp.length != 2) { // ... skip invalid values (this will likely fail signature verification)
                continue;
            }
            String key = URLDecoder.decode(tmp[0], StandardCharsets.UTF_8); // decoded GET query attribute key
            String val = URLDecoder.decode(tmp[1], StandardCharsets.UTF_8); // decoded GET query attribute value
            Map<String, String> pair = new HashMap<>();
            pair.put(KEY, key);
            pair.put(VAL, val);
            items.add(pair);
        }

        // Sort the query key pair collection
        items.sort((left, right) -> {
            String leftKey = left.get(KEY);
            String leftVal = left.get(VAL);
            String rightKey = right.get(KEY);
            String rightVal = right.get(VAL);
            if (leftKey != null && leftKey.equals(rightKey)) {
                return leftVal != null ? leftVal.compareTo(rightVal) : -1;
            } else {
                return leftKey != null ? leftKey.compareTo(rightKey) : -1;
            }
        });

        // Serialize the sorted items back to the signature base string
        StringBuilder signatureBaseString = new StringBuilder();
        boolean firstSkipped = false;
        for (Map<String, String> pair : items) {
            String key = pair.get(KEY);
            String val = pair.get(VAL);
            if (firstSkipped) { // ... for all items except for the first one, prepend "&"
                signatureBaseString.append("&");
            } else {
                firstSkipped = true;
            }
            signatureBaseString.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            signatureBaseString.append("=");
            signatureBaseString.append(URLEncoder.encode(val, StandardCharsets.UTF_8));
        }

        return !signatureBaseString.isEmpty() ? signatureBaseString.toString() : null;
    }

}
