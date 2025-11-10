/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.dh;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.Kem;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * DHKEM implementation as a KEM implemented over ECDHE with curve P-384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class DhKem implements Kem {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final byte[] INFO = "DHKEM-P384".getBytes(StandardCharsets.UTF_8);
    private static final int SHARED_SECRET_BYTES_LENGTH = 48;

    private final HPKE hpke = new HPKE(
            HPKE.mode_base,
            HPKE.kem_P384_SHA384,
            HPKE.kdf_HKDF_SHA384,
            HPKE.aead_EXPORT_ONLY
    );

    @Override
    public KeyPair generateKeyPair() throws GenericCryptoException {
        try {
            return KEY_GENERATOR.generateKeyPair(EcCurve.P384);
        } catch (CryptoProviderException e) {
            throw new GenericCryptoException("Could not generate keypair", e);
        }
    }

    @Override
    public SecretKeyWithEncapsulation encapsulate(PublicKey encapsulationKey) throws GenericCryptoException {
        try {
            final AsymmetricKeyParameter keyParameterPublic = PublicKeyFactory.createKey(encapsulationKey.getEncoded());
            final HPKEContextWithEncapsulation senderCtx = hpke.setupBaseS(keyParameterPublic, INFO);
            final byte[] sharedSecret = senderCtx.export(INFO, SHARED_SECRET_BYTES_LENGTH);
            final byte[] encapsulation = senderCtx.getEncapsulation();
            final SecretKey secretKey = new SecretKeySpec(sharedSecret, "RAW");
            return new SecretKeyWithEncapsulation(secretKey, encapsulation);
        } catch (IOException e) {
            throw new GenericCryptoException("Encapsulation failed", e);
        }
    }

    @Override
    public SecretKey decapsulate(PrivateKey decapsulationKey, byte[] ciphertext) throws GenericCryptoException {
        try {
            final ECPrivateKeyParameters privParam = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(decapsulationKey.getEncoded());
            final ECPublicKeyParameters pubParam = toPublicKey(privParam);
            final AsymmetricCipherKeyPair receiverKeyPair = new AsymmetricCipherKeyPair(pubParam, privParam);
            final HPKEContext receiverCtx = hpke.setupBaseR(ciphertext, receiverKeyPair, INFO);
            final byte[] sharedSecret = receiverCtx.export(INFO, SHARED_SECRET_BYTES_LENGTH);
            return new SecretKeySpec(sharedSecret, "RAW");
        } catch (Exception e) {
            throw new GenericCryptoException("Decapsulation failed", e);
        }
    }

    @Override
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException {
        try {
            return KEY_CONVERTOR.convertPublicKeyToBytes(EcCurve.P384, publicKey);
        } catch (CryptoProviderException e) {
            throw new GenericCryptoException("Could not convert public key to bytes", e);
        }
    }

    @Override
    public PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) throws GenericCryptoException {
        try {
            return KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P384, publicKeyBytes);
        } catch (CryptoProviderException | InvalidKeySpecException e) {
            throw new GenericCryptoException("Could not convert bytes to public key", e);
        }
    }

    private ECPublicKeyParameters toPublicKey(ECPrivateKeyParameters privParam) {
        final ECDomainParameters domainParam = privParam.getParameters();
        final ECPoint q = domainParam.getG().multiply(privParam.getD());
        return new ECPublicKeyParameters(q, domainParam);
    }

}
