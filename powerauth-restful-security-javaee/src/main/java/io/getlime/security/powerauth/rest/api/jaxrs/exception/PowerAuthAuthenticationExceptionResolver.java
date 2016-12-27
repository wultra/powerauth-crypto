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

package io.getlime.security.powerauth.rest.api.jaxrs.exception;

import io.getlime.security.powerauth.rest.api.model.entity.ErrorModel;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

/**
 * Class responsible for PowerAuth 2.0 Standard RESTful API exception handling.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Provider
public class PowerAuthAuthenticationExceptionResolver implements ExceptionMapper<PowerAuthAuthenticationException> {

        @Override
        public Response toResponse(PowerAuthAuthenticationException ex) {
            return Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorModel(ex.getDefaultCode(), ex.getMessage()))
                    .build();
        }

}
