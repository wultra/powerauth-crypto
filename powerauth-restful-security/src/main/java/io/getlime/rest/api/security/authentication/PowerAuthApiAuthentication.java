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
package io.getlime.rest.api.security.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class PowerAuthApiAuthentication extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -3790516505615465445L;

	private String activationId;
	private String userId;

	public PowerAuthApiAuthentication() {
		super(null);
	}

	public PowerAuthApiAuthentication(String activationId, String userId) {
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
