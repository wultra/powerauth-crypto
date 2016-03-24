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
package io.getlime.rest.api.security.application;

import java.util.Map;

/**
 * Interface providing method for PowerAuth behavior high-level customization.
 *  
 * @author Petr Dvorak
 *
 */
public interface PowerAuthApplicationConfiguration {
	
	/**
	 * Check if a given application key is allowed in given server instance. Default and suggested behavior
	 * is to simply return true, unless for some reason given application key must be restricted while still
	 * being "supported" in the PowerAuth server database.
	 * @param applicationKey Application key
	 * @return True if the application key is allowed, false otherwise. 
	 */
	public boolean isAllowedApplicationKey(String applicationKey);
	
	/**
	 * In order to minimize number of up-front request, /pa/activation/status end-point may return
	 * any custom state-less object with an information about the service (such as current timestamp,
	 * service outage info, etc.). Default implementation may simply return null.
	 * @return Custom object with state-less information about the API server status.
	 */
	public Map<String, Object> statusServiceCustomObject();

}
