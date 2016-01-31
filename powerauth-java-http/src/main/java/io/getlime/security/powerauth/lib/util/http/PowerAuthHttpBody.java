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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.common.io.BaseEncoding;

public class PowerAuthHttpBody {

	public static String getSignatureBaseString(String httpMethod, String requestUri, String applicationSecret, String nonce, byte[] data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {

		String requestUriHash = "";
		if (requestUri != null) {
			MessageDigest shaUri = MessageDigest.getInstance("SHA-256");
			shaUri.update(requestUri.getBytes("UTF-8"));
			byte[] digest = shaUri.digest();
			requestUriHash = new String(BaseEncoding.base16().encode(digest));
		}

		String dataBase64 = "";
		if (data != null) {
			dataBase64 = BaseEncoding.base64().encode(data);
		}

		return (httpMethod != null ? httpMethod.toUpperCase() : "GET")
				+ "&" + requestUriHash
				+ "&" + applicationSecret
				+ "&" + (nonce != null ? nonce : "")
				+ "&" + dataBase64;
	}

}
