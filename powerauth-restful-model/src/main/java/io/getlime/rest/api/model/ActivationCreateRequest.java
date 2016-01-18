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
package io.getlime.rest.api.model;

public class ActivationCreateRequest {
	
	private String activationIdShort;
	private String activationNonce;
	private String encryptedDevicePublicKey;
	private String activationName;
	private String extras;
	
	public String getActivationIdShort() {
		return activationIdShort;
	}
	
	public void setActivationIdShort(String activationIdShort) {
		this.activationIdShort = activationIdShort;
	}
	
	public String getActivationNonce() {
		return activationNonce;
	}
	
	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}
	
	public String getEncryptedDevicePublicKey() {
		return encryptedDevicePublicKey;
	}
	
	public void setEncryptedDevicePublicKey(String encryptedDevicePublicKey) {
		this.encryptedDevicePublicKey = encryptedDevicePublicKey;
	}
	
	public String getActivationName() {
		return activationName;
	}
	
	public void setActivationName(String activationName) {
		this.activationName = activationName;
	}
	
	public String getExtras() {
		return extras;
	}
	
	public void setExtras(String extras) {
		this.extras = extras;
	}
	
}
