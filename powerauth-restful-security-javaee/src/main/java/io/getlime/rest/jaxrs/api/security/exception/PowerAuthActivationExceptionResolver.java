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

package io.getlime.rest.jaxrs.api.security.exception;

import io.getlime.rest.api.model.entity.ErrorModel;
import io.getlime.rest.api.security.exception.PowerAuthActivationException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthActivationExceptionResolver implements ExceptionMapper<PowerAuthActivationException> {

    @Override
    public Response toResponse(PowerAuthActivationException ex) {
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(new ErrorModel(ex.getDefaultCode(), ex.getMessage()))
                .build();
    }
}
