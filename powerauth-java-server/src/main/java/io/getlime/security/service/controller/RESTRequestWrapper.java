package io.getlime.security.service.controller;

import javax.validation.constraints.NotNull;

public class RESTRequestWrapper<T> {

    @NotNull
    private T requestObject;

    public RESTRequestWrapper() {
    }

    public RESTRequestWrapper(@NotNull T requestObject) {
        this.requestObject = requestObject;
    }

    @NotNull
    public T getRequestObject() {
        return requestObject;
    }

    public void setRequestObject(T requestObject) {
        this.requestObject = requestObject;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((requestObject == null) ? 0 : requestObject.hashCode());
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
		RESTRequestWrapper other = (RESTRequestWrapper) obj;
        if (requestObject == null) {
            if (other.requestObject != null) {
                return false;
            }
        } else if (!requestObject.equals(other.requestObject)) {
            return false;
        }
        return true;
    }

}
