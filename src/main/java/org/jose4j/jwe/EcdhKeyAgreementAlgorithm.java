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

package org.jose4j.jwe;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmAvailability;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwe.kdf.KdfUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 */
public class EcdhKeyAgreementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    String algorithmIdHeaderName = HeaderParameterNames.ENCRYPTION_METHOD;

    public EcdhKeyAgreementAlgorithm()
    {
        setAlgorithmIdentifier(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        setJavaAlgorithm("ECDH");
        setKeyType(EllipticCurveJsonWebKey.KEY_TYPE);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }

    public EcdhKeyAgreementAlgorithm(String algorithmIdHeaderName)
    {
        this();
        this.algorithmIdHeaderName = algorithmIdHeaderName;
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        KeyValidationSupport.cekNotAllowed(cekOverride, getAlgorithmIdentifier());
        ECPublicKey receiversKey = (ECPublicKey) managementKey;
        String keyPairGeneratorProvider = providerContext.getGeneralProviderContext().getKeyPairGeneratorProvider();
        SecureRandom secureRandom = providerContext.getSecureRandom();
        EllipticCurveJsonWebKey ephemeralJwk = EcJwkGenerator.generateJwk(receiversKey.getParams(), keyPairGeneratorProvider, secureRandom);
        return manageForEncrypt(managementKey, cekDesc, headers, ephemeralJwk, providerContext);
    }

    ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, PublicJsonWebKey ephemeralJwk, ProviderContext providerContext) throws JoseException
    {
        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);
        byte[] z = generateEcdhSecret(ephemeralJwk.getPrivateKey(), (PublicKey) managementKey, providerContext);
        byte[] derivedKey = kdf(cekDesc, headers, z, providerContext);
        return new ContentEncryptionKeys(derivedKey, null);
    }

    public CryptoPrimitive prepareForDecrypt(Key managementKey, Headers headers, ProviderContext providerContext) throws JoseException
    {
        String keyFactoryProvider = providerContext.getGeneralProviderContext().getKeyFactoryProvider();
        JsonWebKey ephemeralJwk = headers.getPublicJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, keyFactoryProvider);
        ECPublicKey ephemeralPublicKey = (ECPublicKey) ephemeralJwk.getKey();
        ECPrivateKey privateKey = (ECPrivateKey) managementKey;
        checkPointIsOnCurve(ephemeralPublicKey, privateKey);
        KeyAgreement keyAgreement = createKeyAgreement(privateKey, ephemeralPublicKey, providerContext);
        return new CryptoPrimitive(keyAgreement);
    }

    public Key manageForDecrypt(CryptoPrimitive cryptoPrimitive, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers,  ProviderContext providerContext) throws JoseException
    {
        KeyAgreement keyAgreement = cryptoPrimitive.getKeyAgreement();
        byte[] z = keyAgreement.generateSecret();
        byte[] derivedKey = kdf(cekDesc, headers, z, providerContext);
        String cekAlg = cekDesc.getContentEncryptionKeyAlgorithm();
        return new SecretKeySpec(derivedKey, cekAlg);
    }

    private void checkPointIsOnCurve(ECPublicKey ephemeralPublicKey, ECPrivateKey privateKey) throws JoseException
    {
        // to prevent 'Invalid Curve Attack': for NIST curves, check whether public key is on the private key's curve.
        // from https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf

        // there appear to be similar checks in the JVM starting with 1.8.0_51 but
        // doing it here explicitly seems prudent

        // (y^2) mod p = (x^3 + ax + b) mod p
        // thanks to Antonio Sanso for guidance on how to do this check
        ECParameterSpec ecParameterSpec = privateKey.getParams();
        EllipticCurve curve = ecParameterSpec.getCurve();
        ECPoint point = ephemeralPublicKey.getW();
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger leftSide = (y.pow(2)).mod(p);
        BigInteger rightSide = (x.pow(3).add(a.multiply(x)).add(b)).mod(p);
        boolean onCurve = leftSide.equals(rightSide);
        if (!onCurve)
        {
            throw new JoseException(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY + " is invalid for " + EllipticCurves.getName(curve));
        }
    }

    private byte[] kdf(ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] z, ProviderContext providerContext)
    {
        String messageDigestProvider = providerContext.getGeneralProviderContext().getMessageDigestProvider();
        KdfUtil kdf = new KdfUtil(messageDigestProvider);
        int keydatalen = ByteUtil.bitLength(cekDesc.getContentEncryptionKeyByteLength());
        /*
           AlgorithmID  In the Direct Key Agreement case, this is set to the
          octets of the UTF-8 representation of the "enc" header parameter
          value.  In the Key Agreement with Key Wrapping case, this is set
          to the octets of the UTF-8 representation of the "alg" header
          parameter value.*/
        String algorithmID = headers.getStringHeaderValue(algorithmIdHeaderName);
        String partyUInfo = headers.getStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_U_INFO);
        String partyVInfo = headers.getStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_V_INFO);
        return kdf.kdf(z, keydatalen, algorithmID, partyUInfo, partyVInfo);
    }


    private KeyAgreement getKeyAgreement(String provider) throws JoseException
    {
        String javaAlgorithm = getJavaAlgorithm();
        try
        {
            return provider == null ? KeyAgreement.getInstance(javaAlgorithm) : KeyAgreement.getInstance(javaAlgorithm, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("No " + javaAlgorithm + " KeyAgreement available.", e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Cannot get "+javaAlgorithm+ " KeyAgreement with provider " + provider, e);
        }
    }

    private KeyAgreement createKeyAgreement(PrivateKey privateKey, PublicKey publicKey, ProviderContext providerContext) throws JoseException
    {
        String keyAgreementProvider = providerContext.getSuppliedKeyProviderContext().getKeyAgreementProvider();
        KeyAgreement keyAgreement = getKeyAgreement(keyAgreementProvider);

        try
        {
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new InvalidKeyException("Invalid Key for " + getJavaAlgorithm() + " key agreement - " + e, e);
        }

        return keyAgreement;
    }

    private byte[] generateEcdhSecret(PrivateKey privateKey, PublicKey publicKey, ProviderContext providerContext) throws JoseException
    {
        KeyAgreement keyAgreement = createKeyAgreement(privateKey, publicKey, providerContext);
        return keyAgreement.generateSecret();
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        KeyValidationSupport.castKey(managementKey, ECPublicKey.class);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        KeyValidationSupport.castKey(managementKey, ECPrivateKey.class);
    }

    @Override
    public boolean isAvailable()
    {
        EcKeyUtil ecKeyUtil = new EcKeyUtil();
        return ecKeyUtil.isAvailable() && AlgorithmAvailability.isAvailable("KeyAgreement", getJavaAlgorithm());
    }
}
