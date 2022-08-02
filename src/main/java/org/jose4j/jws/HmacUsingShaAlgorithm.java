/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jws;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmAvailability;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.jose4j.mac.MacUtil;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 */
public class HmacUsingShaAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    private int minimumKeyLength;

    public HmacUsingShaAlgorithm(String id, String javaAlgo, int minimumKeyLength)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(OctetSequenceJsonWebKey.KEY_TYPE);
        this.minimumKeyLength = minimumKeyLength;
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes, ProviderContext providerContext) throws JoseException
    {
        if (!(key instanceof SecretKey))
        {
            throw new InvalidKeyException(key.getClass() + " cannot be used for HMAC verification.");
        }

        Mac mac = getMacInstance(key, providerContext);
        byte[] calculatedSigature = mac.doFinal(securedInputBytes);

        return ByteUtil.secureEquals(signatureBytes, calculatedSigature);
    }

    @Override
    public CryptoPrimitive prepareForSign(Key key, ProviderContext providerContext) throws JoseException
    {
        Mac mac = getMacInstance(key, providerContext);
        return new CryptoPrimitive(mac);
    }

    public byte[] sign(CryptoPrimitive cryptoPrimitive, byte[] securedInputBytes) throws JoseException
    {
        Mac mac = cryptoPrimitive.getMac();
        return mac.doFinal(securedInputBytes);
    }

    private Mac getMacInstance(Key key, ProviderContext providerContext) throws JoseException
    {
        String macProvider = providerContext.getSuppliedKeyProviderContext().getMacProvider();
        return MacUtil.getInitializedMac(getJavaAlgorithm(), key, macProvider);
    }

    void validateKey(Key key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }

        if (key.getEncoded() != null)
        {
            int length = ByteUtil.bitLength(key.getEncoded());
            if (length < minimumKeyLength)
            {
                throw new InvalidKeyException("A key of the same size as the hash output (i.e. "+minimumKeyLength+
                        " bits for "+getAlgorithmIdentifier()+
                        ") or larger MUST be used with the HMAC SHA algorithms but this key is only " + length + " bits");
            }
        }
    }

    public void validateSigningKey(Key key) throws InvalidKeyException
    {
        validateKey(key);
    }

    public void validateVerificationKey(Key key) throws InvalidKeyException
    {
        validateKey(key);
    }

    @Override
    public boolean isAvailable()
    {
        try
        {
            Mac.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            return false;
        }
        return true;
    }

    public static class HmacSha256 extends HmacUsingShaAlgorithm
    {
        public HmacSha256()
        {
            super(AlgorithmIdentifiers.HMAC_SHA256, MacUtil.HMAC_SHA256, 256);
        }
    }

    public static class HmacSha384 extends HmacUsingShaAlgorithm
    {
        public HmacSha384()
        {
            super(AlgorithmIdentifiers.HMAC_SHA384, MacUtil.HMAC_SHA384, 384);
        }
    }

    public static class HmacSha512 extends HmacUsingShaAlgorithm
    {
        public HmacSha512()
        {
            super(AlgorithmIdentifiers.HMAC_SHA512, MacUtil.HMAC_SHA512, 512);
        }
    }
}
