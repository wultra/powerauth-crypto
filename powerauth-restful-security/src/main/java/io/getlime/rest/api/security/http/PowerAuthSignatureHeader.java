package io.getlime.rest.api.security.http;

import java.util.Map;

import com.google.common.base.Splitter;

public class PowerAuthSignatureHeader {
	
	public static final String ACTIVATION_ID = "pa_activation_id";
	public static final String APPLICATION_ID = "pa_application_id";
	public static final String SIGNATURE = "pa_signature";
	public static final String SIGNATURE_TYPE = "pa_signature_type";
	public static final String NONCE = "pa_nonce";
	public static final String VERSION = "pa_version";
	
	private static final String POWERAUTH_PREFIX = "PowerAuth ";

	public static Map<String, String> parsePowerAuthSignatureHTTPHeader(String xPowerAuthSignatureHeader) {
		xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.trim();
		if (!xPowerAuthSignatureHeader.startsWith(POWERAUTH_PREFIX)) {
			return null;
		}
		xPowerAuthSignatureHeader.substring(POWERAUTH_PREFIX.length());
		Map<String, String> result = Splitter.onPattern("\\s(?=([^\\\"]*\\\"[^\\\"]*\\\")*[^\\\"]*$)")
				.withKeyValueSeparator(Splitter.onPattern("=")).split(xPowerAuthSignatureHeader);
		return result;
	}

}
