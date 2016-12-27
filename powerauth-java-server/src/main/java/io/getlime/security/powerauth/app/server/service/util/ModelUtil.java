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
package io.getlime.security.powerauth.app.server.service.util;

import io.getlime.security.powerauth.app.server.repository.model.ActivationStatus;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Utility class used for conversion between model data types.
 *
 * @author Petr Dvorak
 */
public class ModelUtil {

    /**
     * Convert between activation status repository and SOAP service enum.
     *
     * @param repositoryStatus Repository status representation.
     * @return SOAP service status representation.
     */
    public static io.getlime.security.powerauth.ActivationStatus toServiceStatus(
            ActivationStatus repositoryStatus) {
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

    /**
     * Convert between Date and XMLGregorianCalendar.
     *
     * @param date Date instance
     * @return XMLGregorianCalendar instance
     * @throws DatatypeConfigurationException In case data conversion fails
     */
    public static XMLGregorianCalendar calendarWithDate(Date date) throws DatatypeConfigurationException {
        if (date == null) {
            return null;
        }
        GregorianCalendar c = new GregorianCalendar();
        c.setTime(date);
        XMLGregorianCalendar date2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
        return date2;
    }

    /**
     * Convert between Date and XMLGregorianCalendar.
     *
     * @param calendar XMLGregorianCalendar instance
     * @return Date instance
     * @throws DatatypeConfigurationException In case data conversion fails
     */
    public static Date dateWithCalendar(XMLGregorianCalendar calendar) throws DatatypeConfigurationException {
        if (calendar == null) {
            return null;
        }
        return calendar.toGregorianCalendar().getTime();
    }

}
