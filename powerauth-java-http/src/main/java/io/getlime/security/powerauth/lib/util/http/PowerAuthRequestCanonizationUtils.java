package io.getlime.security.powerauth.lib.util.http;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;

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
     * Take the GET request query string (for example, "param1=key1&param2=key2") and convert it to the
     * canonized form by sorting the key value pairs primarily by keys and by values in case the keys are
     * equal.
     *
     * @param queryString The original get query string, obtained for example by 'request.getQueryString();'.
     * @return Canonized query string.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported.
     */
    public static String canonizeGetParameters(String queryString) throws UnsupportedEncodingException {
        List<Map<String, String>> items = new ArrayList<>();
        String[] keyValuePairs = queryString.split("&"); // ... get the key value pairs
        for (String keyValue : keyValuePairs) {
            String[] tmp = keyValue.split("=", 1);
            if (tmp.length != 2) { // ... skip invalid values (this will likely fail signature verification)
                continue;
            }
            String key = URLDecoder.decode(tmp[0], "UTF-8"); // decoded GET query attribute key
            String val = URLDecoder.decode(tmp[1], "UTF-8"); // decoded GET query attribute value
            Map<String, String> pair = new HashMap<>();
            pair.put(KEY, key);
            pair.put(VAL, val);
            items.add(pair);
        }

        // Sort the query key pair collection
        Collections.sort(items, new Comparator<Map<String, String>>() {
            @Override
            public int compare(Map<String, String> left, Map<String, String> right) {
                String leftKey = left.get(KEY);
                String leftVal = left.get(VAL);
                String rightKey = right.get(KEY);
                String rightVal = right.get(VAL);
                if (leftKey != null && leftKey.equals(rightKey)) {
                    return leftVal != null ? leftVal.compareTo(rightVal) : -1;
                } else {
                    return leftKey != null ? leftKey.compareTo(rightKey) : -1;
                }
            }
        });

        // Serialize the sorted items back to the signature base string
        String signatureBaseString = "";
        boolean firstSkipped = false;
        for (Map<String, String> pair : items) {
            String key = pair.get(KEY);
            String val = pair.get(VAL);
            if (firstSkipped) { // ... for all items except for the first one, prepend "&"
                signatureBaseString += "&";
            } else {
                firstSkipped = true;
            }
            signatureBaseString += URLEncoder.encode(key, "UTF-8");
            signatureBaseString += "=";
            signatureBaseString += URLEncoder.encode(val, "UTF-8");
        }

        return signatureBaseString.length() > 0 ? signatureBaseString : null;
    }

}
