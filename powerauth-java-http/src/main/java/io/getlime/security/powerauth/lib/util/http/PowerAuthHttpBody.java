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
package io.getlime.security.powerauth.lib.util.http;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import com.google.common.io.BaseEncoding;

public class PowerAuthHttpBody {

	public static String getSignatureBaseString(String httpMethod, String requestUri, byte[] nonce, byte[] data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {

		String requestUriHash = "";
		if (requestUri != null) {
			requestUriHash = new String(BaseEncoding.base64().encode(requestUri.getBytes("UTF-8")));
		}

		String dataBase64 = "";
		if (data != null) {
			dataBase64 = BaseEncoding.base64().encode(data);
		}
		
		String nonceBase64 = "";
		if (nonce != null) {
			nonceBase64 = BaseEncoding.base64().encode(nonce);
		}

		return (httpMethod != null ? httpMethod.toUpperCase() : "GET")
				+ "&" + requestUriHash
				+ "&" + nonceBase64
				+ "&" + dataBase64;
	}

}
