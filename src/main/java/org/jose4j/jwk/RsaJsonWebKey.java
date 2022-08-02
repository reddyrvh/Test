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

package org.jose4j.jwk;

import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 */
public class RsaJsonWebKey extends PublicJsonWebKey
{
    public static final String MODULUS_MEMBER_NAME = "n";
    public static final String EXPONENT_MEMBER_NAME = "e";

    public static final String PRIVATE_EXPONENT_MEMBER_NAME = "d";

    public static final String FIRST_PRIME_FACTOR_MEMBER_NAME = "p";
    public static final String SECOND_PRIME_FACTOR_MEMBER_NAME = "q";
    public static final String FIRST_FACTOR_CRT_EXPONENT_MEMBER_NAME = "dp";
    public static final String SECOND_FACTOR_CRT_EXPONENT_MEMBER_NAME = "dq";
    public static final String FIRST_CRT_COEFFICIENT_MEMBER_NAME = "qi";

    // and what about RSAMultiPrimePrivateCrtKey...  not yet todo
    public static final String OTHER_PRIMES_INFO_MEMBER_NAME = "oth";
    public static final String PRIME_FACTOR_OTHER_MEMBER_NAME = "r";
    public static final String FACTOR_CRT_EXPONENT_OTHER_MEMBER_NAME = "d";
    public static final String FACTOR_CRT_COEFFICIENT = "t";

    public static final String KEY_TYPE = "RSA";

    public RsaJsonWebKey(RSAPublicKey publicKey)
    {
        super(publicKey);
    }

    public RsaJsonWebKey(Map<String, Object> params) throws JoseException
    {
        this(params, null);
    }

    public RsaJsonWebKey(Map<String, Object> params, String jcaProvider) throws JoseException
    {
        super(params, jcaProvider);

        BigInteger modulus = getBigIntFromBase64UrlEncodedParam(params, MODULUS_MEMBER_NAME, true);

        BigInteger publicExponent = getBigIntFromBase64UrlEncodedParam(params, EXPONENT_MEMBER_NAME, true);

        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil(jcaProvider, null);
        key = rsaKeyUtil.publicKey(modulus, publicExponent);
        checkForBareKeyCertMismatch();

        if (params.containsKey(PRIVATE_EXPONENT_MEMBER_NAME))
        {
            BigInteger d = getBigIntFromBase64UrlEncodedParam(params, PRIVATE_EXPONENT_MEMBER_NAME, false);

            if (params.containsKey(FIRST_PRIME_FACTOR_MEMBER_NAME))
            {
                BigInteger p = getBigIntFromBase64UrlEncodedParam(params, FIRST_PRIME_FACTOR_MEMBER_NAME, false);
                BigInteger q = getBigIntFromBase64UrlEncodedParam(params, SECOND_PRIME_FACTOR_MEMBER_NAME, false);
                BigInteger dp = getBigIntFromBase64UrlEncodedParam(params, FIRST_FACTOR_CRT_EXPONENT_MEMBER_NAME, false);
                BigInteger dq = getBigIntFromBase64UrlEncodedParam(params, SECOND_FACTOR_CRT_EXPONENT_MEMBER_NAME, false);
                BigInteger qi = getBigIntFromBase64UrlEncodedParam(params, FIRST_CRT_COEFFICIENT_MEMBER_NAME, false);
                privateKey = rsaKeyUtil.privateKey(modulus, publicExponent, d, p, q, dp, dq, qi);
            }
            else
            {
                privateKey = rsaKeyUtil.privateKey(modulus, d);
            }
        }

        removeFromOtherParams(MODULUS_MEMBER_NAME,
                EXPONENT_MEMBER_NAME,
                PRIVATE_EXPONENT_MEMBER_NAME,
                FIRST_PRIME_FACTOR_MEMBER_NAME,
                SECOND_PRIME_FACTOR_MEMBER_NAME,
                FIRST_FACTOR_CRT_EXPONENT_MEMBER_NAME,
                SECOND_FACTOR_CRT_EXPONENT_MEMBER_NAME,
                FIRST_CRT_COEFFICIENT_MEMBER_NAME);
    }

    public String getKeyType()
    {
        return KEY_TYPE;
    }

    public RSAPublicKey getRsaPublicKey()
    {
        return (RSAPublicKey) key;
    }

    /**
     * @deprecated deprecated in favor of the more consistently named {@link #getRsaPublicKey()}
     * @return RSAPublicKey
     */
    public RSAPublicKey getRSAPublicKey()
    {
        return getRsaPublicKey();
    }

    public RSAPrivateKey getRsaPrivateKey()
    {
        return (RSAPrivateKey) privateKey;
    }

    protected void fillPublicTypeSpecificParams(Map<String,Object> params)
    {
        RSAPublicKey rsaPublicKey = getRsaPublicKey();
        putBigIntAsBase64UrlEncodedParam(params, MODULUS_MEMBER_NAME, rsaPublicKey.getModulus());
        putBigIntAsBase64UrlEncodedParam(params, EXPONENT_MEMBER_NAME, rsaPublicKey.getPublicExponent());
    }

    protected void fillPrivateTypeSpecificParams(Map<String,Object> params)
    {
        RSAPrivateKey rsaPrivateKey = getRsaPrivateKey();
        
        if (rsaPrivateKey != null) 
        {
            putBigIntAsBase64UrlEncodedParam(params, PRIVATE_EXPONENT_MEMBER_NAME, rsaPrivateKey.getPrivateExponent());

	        if (rsaPrivateKey instanceof RSAPrivateCrtKey)
	        {
	            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) rsaPrivateKey;
	            putBigIntAsBase64UrlEncodedParam(params, FIRST_PRIME_FACTOR_MEMBER_NAME, crt.getPrimeP());
	            putBigIntAsBase64UrlEncodedParam(params, SECOND_PRIME_FACTOR_MEMBER_NAME, crt.getPrimeQ());
	            putBigIntAsBase64UrlEncodedParam(params, FIRST_FACTOR_CRT_EXPONENT_MEMBER_NAME, crt.getPrimeExponentP());
	            putBigIntAsBase64UrlEncodedParam(params, SECOND_FACTOR_CRT_EXPONENT_MEMBER_NAME, crt.getPrimeExponentQ());
	            putBigIntAsBase64UrlEncodedParam(params, FIRST_CRT_COEFFICIENT_MEMBER_NAME, crt.getCrtCoefficient());
	        }
        }
    }

    @Override
    protected String produceThumbprintHashInput()
    {
        String template = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";
        HashMap<String, Object> params = new HashMap<>();
        fillPublicTypeSpecificParams(params);
        return String.format(template, params.get(EXPONENT_MEMBER_NAME), params.get(MODULUS_MEMBER_NAME));
    }
}
