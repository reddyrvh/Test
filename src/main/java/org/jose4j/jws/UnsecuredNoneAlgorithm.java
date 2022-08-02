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
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import java.security.Key;

public class UnsecuredNoneAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    private static final String CANNOT_HAVE_KEY_MESSAGE = "JWS Plaintext ("+ HeaderParameterNames.ALGORITHM+"="+ AlgorithmIdentifiers.NONE+") must not use a key.";

    public UnsecuredNoneAlgorithm()
    {
        setAlgorithmIdentifier(AlgorithmIdentifiers.NONE);
        setKeyPersuasion(KeyPersuasion.NONE);
    }

    @Override
    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes, ProviderContext providerContext) throws JoseException
    {
        validateKey(key);

        return (signatureBytes.length == 0);
    }

    @Override
    public CryptoPrimitive prepareForSign(Key key, ProviderContext providerContext) throws JoseException
    {
        validateKey(key);
        return null;
    }

    @Override
    public byte[] sign(CryptoPrimitive cryptoPrimitive, byte[] securedInputBytes)
    {
        return ByteUtil.EMPTY_BYTES;
    }

    @Override
    public void validateSigningKey(Key key) throws InvalidKeyException
    {
        validateKey(key);
    }

    @Override
    public void validateVerificationKey(Key key) throws InvalidKeyException
    {
        validateKey(key);
    }

    private void validateKey(Key key) throws InvalidKeyException
    {
        if (key != null)
        {
            throw new InvalidKeyException(CANNOT_HAVE_KEY_MESSAGE);
        }
    }

    @Override
    public boolean isAvailable()
    {
        return true;
    }
}
