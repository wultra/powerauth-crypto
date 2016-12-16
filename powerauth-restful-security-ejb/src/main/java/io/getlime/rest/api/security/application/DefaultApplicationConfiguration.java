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

package io.getlime.rest.api.security.application;

import javax.enterprise.inject.Default;
import java.util.Map;

/**
 * Default (empty) implementation of application configuration.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Default
public class DefaultApplicationConfiguration implements PowerAuthApplicationConfiguration {


    @Override public boolean isAllowedApplicationKey(String applicationKey) {
        return true;
    }

    @Override public Map<String, Object> statusServiceCustomObject() {
        return null;
    }
}
