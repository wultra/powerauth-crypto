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

import java.util.Map;

public class ActivationStatusResponse {
	
	private String activationId;
	private String encryptedStatusBlob;
	private Map<String, Object> customObject;
	
	public String getActivationId() {
		return activationId;
	}
	
	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getEncryptedStatusBlob() {
		return encryptedStatusBlob;
	}
	
	public void setEncryptedStatusBlob(String cStatusBlob) {
		this.encryptedStatusBlob = cStatusBlob;
	}
	
	public Map<String, Object> getCustomObject() {
		return customObject;
	}
	
	public void setCustomObject(Map<String, Object> customObject) {
		this.customObject = customObject;
	}

}
