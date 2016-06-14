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

/**
 * Request object for /pa/activation/create end-point.
 * 
 * @author Petr Dvorak
 *
 */
public class ActivationCreateRequest {
	
	private String activationIdShort;
	private String activationNonce;
	private String ephemeralPublicKey;
	private String encryptedDevicePublicKey;
	private String activationName;
	private String extras;
	private String applicationKey;
	private String applicationSignature;
	
	/**
	 * Get activation ID short.
	 * @return Activation ID short.
	 */
	public String getActivationIdShort() {
		return activationIdShort;
	}
	
	/**
	 * Set activation ID short.
	 * @param activationIdShort Activation ID short.
	 */
	public void setActivationIdShort(String activationIdShort) {
		this.activationIdShort = activationIdShort;
	}
	
	/**
	 * Get activation nonce.
	 * @return Activation nonce.
	 */
	public String getActivationNonce() {
		return activationNonce;
	}
	
	/**
	 * Set activation nonce.
	 * @param activationNonce Activation nonce.
	 */
	public void setActivationNonce(String activationNonce) {
		this.activationNonce = activationNonce;
	}
	
	/**
	 * Get the ephemeral public key.
	 * @return Ephemeral public key.
	 */
	public String getEphemeralPublicKey() {
		return ephemeralPublicKey;
	}
	
	/**
	 * Set the ephemeral public key.
	 * @param ephemeralPublicKey Ephemeral public key.
	 */
	public void setEphemeralPublicKey(String ephemeralPublicKey) {
		this.ephemeralPublicKey = ephemeralPublicKey;
	}
	
	/**
	 * Get encrypted device public key.
	 * @return cDevicePublicKey
	 */
	public String getEncryptedDevicePublicKey() {
		return encryptedDevicePublicKey;
	}
	
	/**
	 * Set encrypted device public key.
	 * @param encryptedDevicePublicKey Encrypted device public key.
	 */
	public void setEncryptedDevicePublicKey(String encryptedDevicePublicKey) {
		this.encryptedDevicePublicKey = encryptedDevicePublicKey;
	}
	
	/**
	 * Get activation name.
	 * @return Activation name.
	 */
	public String getActivationName() {
		return activationName;
	}
	
	/**
	 * Set activation name.
	 * @param activationName Activation name.
	 */
	public void setActivationName(String activationName) {
		this.activationName = activationName;
	}
	
	/**
	 * Get extra parameter.
	 * @return Extra parameter.
	 */
	public String getExtras() {
		return extras;
	}
	
	/**
	 * Set extra parameter.
	 * @param extras Extra parameter.
	 */
	public void setExtras(String extras) {
		this.extras = extras;
	}
	
	/**
	 * Get application key.
	 * @return Application key.
	 */
	public String getApplicationKey() {
		return applicationKey;
	}
	
	/**
	 * Set application key.
	 * @param applicationKey Application key.
	 */
	public void setApplicationKey(String applicationKey) {
		this.applicationKey = applicationKey;
	}
	
	/**
	 * Get application signature.
	 * @return Application signature.
	 */
	public String getApplicationSignature() {
		return applicationSignature;
	}
	
	/**
	 * Set application signature.
	 * @param applicationSignature Application signature.
	 */
	public void setApplicationSignature(String applicationSignature) {
		this.applicationSignature = applicationSignature;
	}
	
}
