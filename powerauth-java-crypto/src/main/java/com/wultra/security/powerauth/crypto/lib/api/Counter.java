/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.crypto.lib.api;

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

/**
 * Interface for byte array based counter used for cryptography.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public interface Counter {

    /**
     * Initialize counter by generating initial counter data.
     * @return Initial counter data.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case of invalid initialization.
     */
    byte[] init() throws CryptoProviderException, GenericCryptoException;

    /**
     * Generate next counter data based on current counter data.
     * @param ctrData Current counter data.
     * @return Next counter data.
     * @throws GenericCryptoException In case next counter value could not be derived.
     */
    byte[] next(byte[] ctrData) throws GenericCryptoException;

}
