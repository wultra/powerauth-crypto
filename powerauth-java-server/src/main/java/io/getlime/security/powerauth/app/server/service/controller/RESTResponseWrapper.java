/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.service.controller;

import javax.validation.constraints.NotNull;

/**
 * Base class for RESTful response object.
 *
 * @param <T> Type of the response object instance.
 * @author Petr Dvorak
 */
public class RESTResponseWrapper<T> {

    @NotNull
    private T responseObject;

    @NotNull
    private String status;

    /**
     * Default constructor.
     */
    public RESTResponseWrapper() {
    }

    /**
     * Constructor with status and response object.
     *
     * @param status         Status - "OK" or "ERROR".
     * @param responseObject Response object instance.
     */
    public RESTResponseWrapper(@NotNull String status, @NotNull T responseObject) {
        this.status = status;
        this.responseObject = responseObject;
    }

    /**
     * Get response object.
     *
     * @return Response object.
     */
    public T getResponseObject() {
        return responseObject;
    }

    /**
     * Set response object.
     *
     * @param responseObject Response object.
     */
    public void setResponseObject(T responseObject) {
        this.responseObject = responseObject;
    }

    /**
     * Get response status.
     *
     * @return Status.
     */
    public String getStatus() {
        return status;
    }

    /**
     * Set response status.
     *
     * @param status Status.
     */
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
