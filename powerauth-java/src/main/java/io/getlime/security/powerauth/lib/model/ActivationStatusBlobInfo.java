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
