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

import org.jose4j.json.JsonUtil;
import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 */
public abstract class PublicJsonWebKey extends JsonWebKey
{
    public static final String X509_CERTIFICATE_CHAIN_PARAMETER = "x5c";
    public static final String X509_THUMBPRINT_PARAMETER = "x5t";
    public static final String X509_SHA256_THUMBPRINT_PARAMETER = "x5t#S256";
    public static final String X509_URL_PARAMETER = "x5u";

    protected boolean writeOutPrivateKeyToJson;
    protected PrivateKey privateKey;

    protected String jcaProvider;

    private List<X509Certificate> certificateChain;
    private String x5t;
    private String x5tS256;
    private String x5u;

    protected PublicJsonWebKey(PublicKey publicKey)
    {
        super(publicKey);
    }

    protected PublicJsonWebKey(Map<String, Object> params) throws JoseException
    {
        this(params, null);
    }

    protected PublicJsonWebKey(Map<String,Object> params, String jcaProvider) throws JoseException
    {
        super(params);
        this.jcaProvider = jcaProvider;

        if (params.containsKey(X509_CERTIFICATE_CHAIN_PARAMETER))
        {
            List<String> x5cStrings = JsonHelp.getStringArray(params, X509_CERTIFICATE_CHAIN_PARAMETER);
            certificateChain = new ArrayList<X509Certificate>(x5cStrings.size());

            X509Util x509Util = X509Util.getX509Util(jcaProvider);

            for (String b64EncodedDer : x5cStrings)
            {
                X509Certificate x509Certificate = x509Util.fromBase64Der(b64EncodedDer);
                certificateChain.add(x509Certificate);
            }
        }

        x5t = getString(params, X509_THUMBPRINT_PARAMETER);
        x5tS256 = getString(params, X509_SHA256_THUMBPRINT_PARAMETER);

        x5u = getString(params, X509_URL_PARAMETER);

        removeFromOtherParams(X509_CERTIFICATE_CHAIN_PARAMETER,
                X509_SHA256_THUMBPRINT_PARAMETER,
                X509_THUMBPRINT_PARAMETER,
                X509_URL_PARAMETER);
    }

    protected abstract void fillPublicTypeSpecificParams(Map<String,Object> params);
    protected abstract void fillPrivateTypeSpecificParams(Map<String,Object> params);

    protected void fillTypeSpecificParams(Map<String,Object> params, OutputControlLevel outputLevel)
    {
        fillPublicTypeSpecificParams(params);

        if (certificateChain != null)
        {
            X509Util x509Util = new X509Util();
            List<String> x5cStrings = new ArrayList<String>(certificateChain.size());

            for (X509Certificate cert : certificateChain)
            {
               String b64EncodedDer = x509Util.toBase64(cert);
               x5cStrings.add(b64EncodedDer);
            }

            params.put(X509_CERTIFICATE_CHAIN_PARAMETER, x5cStrings);
        }

        putIfNotNull(X509_THUMBPRINT_PARAMETER, x5t, params);
        putIfNotNull(X509_SHA256_THUMBPRINT_PARAMETER, x5tS256, params);
        putIfNotNull(X509_URL_PARAMETER, x5u, params);

        if (writeOutPrivateKeyToJson || outputLevel == OutputControlLevel.INCLUDE_PRIVATE)
        {
            fillPrivateTypeSpecificParams(params);
        }
    }

    public PublicKey getPublicKey()
    {
        return (PublicKey) key;
    }

    /**
     * @deprecated as of 0.3.2 use {@link #toJson(org.jose4j.jwk.JsonWebKey.OutputControlLevel)}
     * @param writeOutPrivateKeyToJson don't use this
     */
    public void setWriteOutPrivateKeyToJson(boolean writeOutPrivateKeyToJson)
    {
        this.writeOutPrivateKeyToJson = writeOutPrivateKeyToJson;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public List<X509Certificate> getCertificateChain()
    {
        return certificateChain;
    }

    public X509Certificate getLeafCertificate()
    {
        return (certificateChain != null && !certificateChain.isEmpty()) ? certificateChain.get(0) : null;
    }

    public String getX509CertificateSha1Thumbprint()
    {
        return getX509CertificateSha1Thumbprint(false);
    }

    public String getX509CertificateSha1Thumbprint(boolean allowFallbackDeriveFromX5c)
    {
        String result = x5t;
        if (result == null && allowFallbackDeriveFromX5c)
        {
            X509Certificate leafCertificate = getLeafCertificate();
            if (leafCertificate != null)
            {
                result = X509Util.x5t(leafCertificate);
            }
        }

        return result;
    }

    public String getX509CertificateSha256Thumbprint()
    {
        return getX509CertificateSha256Thumbprint(false);
    }

    public String getX509CertificateSha256Thumbprint(boolean allowFallbackDeriveFromX5c)
    {
        String result = x5tS256;
        if (result == null && allowFallbackDeriveFromX5c)
        {
            X509Certificate leafCertificate = getLeafCertificate();
            if (leafCertificate != null)
            {
                result = X509Util.x5tS256(leafCertificate);
            }
        }

        return result;
    }

    public String getX509Url()
    {
        return x5u;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain)
    {
        checkForBareKeyCertMismatch();

        this.certificateChain = certificateChain;
    }

    public void setX509CertificateSha1Thumbprint(String x5t)
    {
        this.x5t = x5t;
    }

    public void setX509CertificateSha256Thumbprint(String x5tS2)
    {
        x5tS256 = x5tS2;
    }

    public void setX509Url(String x5u)
    {
        this.x5u = x5u;
    }

    void checkForBareKeyCertMismatch()
    {
        X509Certificate leafCertificate = getLeafCertificate();
        boolean certAndBareKeyMismatch = leafCertificate != null && !leafCertificate.getPublicKey().equals(getPublicKey());
        if (certAndBareKeyMismatch)
        {
            throw new IllegalArgumentException( "The key in the first certificate MUST match the bare public key " +
                "represented by other members of the JWK. Public key = " + getPublicKey() + " cert = " + leafCertificate);
        }
    }

    public void setCertificateChain(X509Certificate... certificates)
    {
        setCertificateChain(Arrays.asList(certificates));
    }

    BigInteger getBigIntFromBase64UrlEncodedParam(Map<String, Object> params, String parameterName, boolean required) throws JoseException
    {
        String base64UrlValue = getString(params, parameterName, required);
        return BigEndianBigInteger.fromBase64Url(base64UrlValue);
    }

    void putBigIntAsBase64UrlEncodedParam(Map<String,Object> params, String parameterName, BigInteger value)
    {
        String base64UrlValue = BigEndianBigInteger.toBase64Url(value);
        params.put(parameterName, base64UrlValue);
    }

    void putBigIntAsBase64UrlEncodedParam(Map<String,Object> params, String parameterName, BigInteger value, int minLength)
    {
        String base64UrlValue = BigEndianBigInteger.toBase64Url(value, minLength);
        params.put(parameterName, base64UrlValue);
    }

    public static class Factory
    {
        public static PublicJsonWebKey newPublicJwk(Map<String,Object> params, String jcaProvider) throws JoseException
        {
            String kty = getStringRequired(params, KEY_TYPE_PARAMETER);

            switch (kty)
            {
                case RsaJsonWebKey.KEY_TYPE:
                    return new RsaJsonWebKey(params, jcaProvider);
                case EllipticCurveJsonWebKey.KEY_TYPE:
                    return new EllipticCurveJsonWebKey(params, jcaProvider);
                default:
                    throw new JoseException("Unknown key type (for public keys): '" + kty + "'");
            }
        }

        public static PublicJsonWebKey newPublicJwk(Map<String,Object> params) throws JoseException
        {
            return newPublicJwk(params, null);
        }

        public static PublicJsonWebKey newPublicJwk(Key publicKey) throws JoseException
        {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(publicKey);
            return (PublicJsonWebKey) jsonWebKey;
        }

        public static PublicJsonWebKey newPublicJwk(String json) throws JoseException
        {
            return newPublicJwk(json, null);
        }

        public static PublicJsonWebKey newPublicJwk(String json, String jcaProvider) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            return newPublicJwk(parsed, jcaProvider);
        }
    }
}