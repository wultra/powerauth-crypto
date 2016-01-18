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

public class ActivationCreateResponse {
	
	private String activationId;
	private String activationNonce;
	private String ephemeralPublicKey;
	private String encryptedServerPublicKey;
	private String encryptedServerPublicKeySignature;
	
	public String getActivationId() {
		return activationId;
	}
	
	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getActivationNonce() {
		return activationNonce;
	}
	
	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}
	
	public String getEphemeralPublicKey() {
		return ephemeralPublicKey;
	}
	
	public void setEphemeralPublicKey(String ephemeralPublicKey) {
		this.ephemeralPublicKey = ephemeralPublicKey;
	}
	
	public String getEncryptedServerPublicKey() {
		return encryptedServerPublicKey;
	}
	
	public void setEncryptedServerPublicKey(String encryptedServerPublicKey) {
		this.encryptedServerPublicKey = encryptedServerPublicKey;
	}
	
	public String getEncryptedServerPublicKeySignature() {
		return encryptedServerPublicKeySignature;
	}
	
	public void setEncryptedServerPublicKeySignature(String encryptedServerPublicKeySignature) {
		this.encryptedServerPublicKeySignature = encryptedServerPublicKeySignature;
	}

}
