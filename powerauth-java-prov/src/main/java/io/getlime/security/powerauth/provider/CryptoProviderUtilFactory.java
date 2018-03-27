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

package io.getlime.security.powerauth.provider;

import java.security.Security;

/**
 * Factory class for building the correct crypto provider instances.
 *
 * @author Tomáš Vondráček (tomas.vondracek@gmail.com)
 */
public final class CryptoProviderUtilFactory {

    private static CryptoProviderUtil utils;

    /**
     * Return shared (singleton) instance of crypto provider utilities.
     *
     * @return Crypto provider utilities.
     */
    public static synchronized CryptoProviderUtil getCryptoProviderUtils() {
        if (utils == null) {
            final boolean hasBC = Security.getProvider("BC") != null;
            final boolean hasSC = Security.getProvider("SC") != null;

            if (hasBC) {
                utils = new CryptoProviderUtilBouncyCastle();
            } else if (hasSC) {
                utils = new CryptoProviderUtilsSpongyCastle();
            } else {
                throw new IllegalStateException("Neither spongycastle, nor bouncycastle is installed!");
            }
        }
        return utils;
    }
}
