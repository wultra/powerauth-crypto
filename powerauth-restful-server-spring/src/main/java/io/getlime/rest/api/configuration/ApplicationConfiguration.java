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
package io.getlime.rest.api.configuration;

import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * Default implementation of PowerAuthApplicationConfiguration interface. 
 * @author Petr Dvorak
 *
 */
@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {

    @Override
    public boolean isAllowedApplicationKey(String applicationKey) {
        return true;
    }

    @Override
    public Map<String, Object> statusServiceCustomObject() {
        return null;
    }

}
