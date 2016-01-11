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
package io.getlime.rest.api.configuration;

import org.springframework.context.annotation.Configuration;

import io.getlime.rest.api.security.application.PowerAuthApplicationConfiguration;

@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {
	
	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";

	@Override
	public String getApplicationSecretForApplicationId(String applicationId) {
		if (applicationId.equals(ApplicationConfiguration.expectedApplicationId)) {
			return ApplicationConfiguration.expectedApplicationSecret;
		}
		return null;
	}

}
