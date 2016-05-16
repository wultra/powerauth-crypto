/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.io.BaseEncoding;

/**
 * Request filter that intercepts the request body, forwards it to the controller 
 * as a request attribute named "X-PowerAuth-Request-Body" and resets the stream.
 *  
 * @author Petr Dvorak
 *
 */
public class PowerAuthRequestFilter extends OncePerRequestFilter {
	
	/**
	 * Constant for the request attribute name "X-PowerAuth-Request-Body".
	 */
	public static final String POWERAUTH_SIGNATURE_BASE_STRING = "X-PowerAuth-Request-Body";
	
	/**
	 * Utility variable, used for the purpose of GET query attribute sorting (query attribute key).
	 */
	private static final String KEY = "key";
	
	/**
	 * Utility variable, used for the purpose of GET query attribute sorting (query attribute value).
	 */
	private static final String VAL = "val";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		ResettableStreamHttpServletRequest resetableRequest = new ResettableStreamHttpServletRequest(request);
		if (request.getMethod().equals(HttpMethod.GET)) { // ... handle GET method
			List<Map<String,String>> items = new ArrayList<>();
			
			// Parse the query parameters
			String queryString = request.getQueryString();
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
				if (firstSkipped) {
					signatureBaseString += "&";
				} else {
					firstSkipped = true;
				}
				signatureBaseString += URLEncoder.encode(key, "UTF-8");
				signatureBaseString += "=";
				signatureBaseString += URLEncoder.encode(val, "UTF-8");
			}
			
			// Pass the signature base string as the request attribute
			if (signatureBaseString != null) {
				resetableRequest.setAttribute(POWERAUTH_SIGNATURE_BASE_STRING, BaseEncoding.base64().encode(signatureBaseString.getBytes("UTF-8")));
			}
			
		} else { // ... handle POST, PUT, DELETE, ... method
			
			// Get the request body and pass it as the signature base string as the request attribute 
			byte[] body = resetableRequest.getRequestBody();
			if (body != null) {
				resetableRequest.setAttribute(POWERAUTH_SIGNATURE_BASE_STRING, BaseEncoding.base64().encode(body));
			}
		}
		super.doFilter(resetableRequest, response, filterChain);
	}

}
