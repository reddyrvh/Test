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

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.lang.InvalidKeyException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Set;

/**
 */
public class RsaUsingShaAlgorithm extends BaseSignatureAlgorithm implements JsonWebSignatureAlgorithm
{
    static final int TRAILER = 1;
    static final String MGF1 = "MGF1";
    public static final String RSASSA_PSS = "RSASSA-PSS";

    public RsaUsingShaAlgorithm(String id, String javaAlgo)
    {
        super(id, javaAlgo, RsaJsonWebKey.KEY_TYPE);
    }

    public void validatePublicKey(PublicKey key) throws InvalidKeyException
    {
        KeyValidationSupport.checkRsaKeySize(key);
    }

    public void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException
    {
        KeyValidationSupport.checkRsaKeySize(privateKey);
    }

    public static class RsaPssSha256 extends RsaUsingShaAlgorithm
    {
        public RsaPssSha256()
        {
            super(AlgorithmIdentifiers.RSA_PSS_USING_SHA256, choosePssAlgorithmName("SHA256withRSAandMGF1"));
            if (getJavaAlgorithm().equals(RSASSA_PSS))
            {
                MGF1ParameterSpec mgf1pec = MGF1ParameterSpec.SHA256;
                PSSParameterSpec pssSpec = new PSSParameterSpec(mgf1pec.getDigestAlgorithm(), MGF1, mgf1pec, 32, TRAILER);
                setAlgorithmParameterSpec(pssSpec);
            }
        }
    }

    public static class RsaPssSha384 extends RsaUsingShaAlgorithm
    {
        public RsaPssSha384()
        {
            super(AlgorithmIdentifiers.RSA_PSS_USING_SHA384, choosePssAlgorithmName("SHA384withRSAandMGF1"));
            if (getJavaAlgorithm().equals(RSASSA_PSS))
            {
                MGF1ParameterSpec mgf1pec = MGF1ParameterSpec.SHA384;
                PSSParameterSpec pssSpec = new PSSParameterSpec(mgf1pec.getDigestAlgorithm(), MGF1, mgf1pec, 48, TRAILER);
                setAlgorithmParameterSpec(pssSpec);
            }
        }
    }

    public static class RsaPssSha512 extends RsaUsingShaAlgorithm
    {
        public RsaPssSha512()
        {
            super(AlgorithmIdentifiers.RSA_PSS_USING_SHA512, choosePssAlgorithmName("SHA512withRSAandMGF1"));
            if (getJavaAlgorithm().equals(RSASSA_PSS))
            {
                MGF1ParameterSpec mgf1pec = MGF1ParameterSpec.SHA512;
                PSSParameterSpec pssSpec = new PSSParameterSpec(mgf1pec.getDigestAlgorithm(), MGF1, mgf1pec, 64, TRAILER);
                setAlgorithmParameterSpec(pssSpec);
            }
        }
    }

    public static class RsaSha256 extends RsaUsingShaAlgorithm
    {
        public RsaSha256()
        {
            super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA");
        }
    }

    public static class RsaSha384 extends RsaUsingShaAlgorithm
    {
        public RsaSha384()
        {
            super(AlgorithmIdentifiers.RSA_USING_SHA384, "SHA384withRSA");
        }
    }

    public static class RsaSha512 extends RsaUsingShaAlgorithm
    {
        public RsaSha512()
        {
            super(AlgorithmIdentifiers.RSA_USING_SHA512, "SHA512withRSA");
        }
    }

    static String choosePssAlgorithmName(String legacyName)
    {
        Set<String> signatureAlgorithms = Security.getAlgorithms("Signature");
        boolean useLegacyName = Boolean.getBoolean("org.jose4j.jws.use-legacy-rsapss-alg-names");
        return (signatureAlgorithms.contains(RSASSA_PSS) && !useLegacyName) ? RSASSA_PSS : legacyName;
    }
}
