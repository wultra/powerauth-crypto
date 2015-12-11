package io.getlime.rest.api.security.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class ApiAuthentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -3790516505615465445L;

	private String activationId;
	private String userId;

	public ApiAuthentication() {
		super(null);
	}

	public ApiAuthentication(String activationId, String userId) {
		super(null);
		this.activationId = activationId;
		this.userId = userId;
	}

	@Override
	public String getName() {
		return userId;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(1);
		authorities.add(new SimpleGrantedAuthority("USER"));
		return Collections.unmodifiableList(authorities);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return this.userId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getActivationId() {
		return activationId;
	}

	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}

}
