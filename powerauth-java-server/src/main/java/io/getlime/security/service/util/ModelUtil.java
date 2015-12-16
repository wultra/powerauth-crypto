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
package io.getlime.security.service.util;

import java.util.Date;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

public class ModelUtil {

    public static io.getlime.security.powerauth.ActivationStatus toServiceStatus(
            io.getlime.security.repository.model.ActivationStatus repositoryStatus) {
        switch (repositoryStatus) {
            case CREATED:
                return io.getlime.security.powerauth.ActivationStatus.CREATED;
            case OTP_USED:
                return io.getlime.security.powerauth.ActivationStatus.OTP_USED;
            case ACTIVE:
                return io.getlime.security.powerauth.ActivationStatus.ACTIVE;
            case BLOCKED:
                return io.getlime.security.powerauth.ActivationStatus.BLOCKED;
            case REMOVED:
                return io.getlime.security.powerauth.ActivationStatus.REMOVED;
        }
        return io.getlime.security.powerauth.ActivationStatus.REMOVED;
    }
    
    public static XMLGregorianCalendar calendarWithDate(Date date) throws DatatypeConfigurationException {
    	GregorianCalendar c = new GregorianCalendar();
    	c.setTime(date);
    	XMLGregorianCalendar date2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
    	return date2;
    }

}
