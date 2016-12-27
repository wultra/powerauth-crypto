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
 * Base class for RESTful request object.
 *
 * @param <T> Type of the request object instance.
 * @author Petr Dvorak
 */
public class RESTRequestWrapper<T> {

    @NotNull
    private T requestObject;

    /**
     * Default constructor.
     */
    public RESTRequestWrapper() {
    }

    /**
     * Constructor with a correctly typed request object instance.
     *
     * @param requestObject Request object.
     */
    public RESTRequestWrapper(@NotNull T requestObject) {
        this.requestObject = requestObject;
    }

    /**
     * Get request object.
     *
     * @return Request object.
     */
    @NotNull
    public T getRequestObject() {
        return requestObject;
    }

    /**
     * Set request object.
     *
     * @param requestObject Request object.
     */
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
