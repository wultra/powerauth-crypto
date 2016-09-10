package io.getlime.security.powerauth.lib.provider;

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
                throw new IllegalStateException("Neither spongycastne, nor bouncycastle is installed!");
            }
        }
        return utils;
    }
}
