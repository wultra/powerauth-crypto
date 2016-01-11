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
package io.getlime.security.powerauth.lib.model;

public class ActivationStatusBlobInfo {
	
	private boolean valid;
	private byte activationStatus;
	private long counter;
	private byte failedAttempts;
	
	public boolean isValid() {
		return valid;
	}
	
	public void setValid(boolean valid) {
		this.valid = valid;
	}
	
	public byte getActivationStatus() {
		return activationStatus;
	}
	
	public void setActivationStatus(byte activationStatus) {
		this.activationStatus = activationStatus;
	}
	
	public long getCounter() {
		return counter;
	}
	
	public void setCounter(long counter) {
		this.counter = counter;
	}
	
	public byte getFailedAttempts() {
		return failedAttempts;
	}
	
	public void setFailedAttempts(byte failedAttempts) {
		this.failedAttempts = failedAttempts;
	}
	
}
