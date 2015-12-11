package io.getlime.rest.api.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class PowerAuthAuthentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 6495166873663643144L;

	private String activationId;
	private String applicationSecret;
	private String signature;
	private String signatureType;
	private String requestUri;
	private String httpMethod;
	private String nonce;
	private byte[] data;

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

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getApplicationSecret() {
		return applicationSecret;
	}
	
	public void setApplicationSecret(String applicationSecret) {
		this.applicationSecret = applicationSecret;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}
	
	public String getSignatureType() {
		return signatureType;
	}
	
	public void setSignatureType(String signatureType) {
		this.signatureType = signatureType;
	}

	public String getRequestUri() {
		return requestUri;
	}

	public void setRequestUri(String requestUri) {
		this.requestUri = requestUri;
	}

	public String getHttpMethod() {
		return httpMethod;
	}

	public void setHttpMethod(String httpMethod) {
		this.httpMethod = httpMethod;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

}
