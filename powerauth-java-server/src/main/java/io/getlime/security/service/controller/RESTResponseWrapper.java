package io.getlime.security.service.controller;

import javax.validation.constraints.NotNull;

public class RESTResponseWrapper<T> {

    @NotNull
    private T responseObject;

    @NotNull
    private String status;

    public RESTResponseWrapper() {
    }

    public RESTResponseWrapper(@NotNull String status, @NotNull T responseObject) {
        this.status = status;
        this.responseObject = responseObject;
    }

    public T getResponseObject() {
        return responseObject;
    }

    public void setResponseObject(T responseObject) {
        this.responseObject = responseObject;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((responseObject == null) ? 0 : responseObject.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        @SuppressWarnings("rawtypes")
		RESTResponseWrapper other = (RESTResponseWrapper) obj;
        if (responseObject == null) {
            if (other.responseObject != null) {
                return false;
            }
        } else if (!responseObject.equals(other.responseObject)) {
            return false;
        }
        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
            return false;
        }
        return true;
    }

}
