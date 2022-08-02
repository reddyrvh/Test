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
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 */
public abstract class BaseSignatureAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private AlgorithmParameterSpec algorithmParameterSpec;

    public BaseSignatureAlgorithm(String id, String javaAlgo, String keyAlgo)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
        setKeyType(keyAlgo);
    }

    protected void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec)
    {
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    @Override
    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes, ProviderContext providerContext) throws JoseException
    {
        Signature signature = getSignature(providerContext);
        initForVerify(signature, key);
        try
        {
            signature.update(securedInputBytes);
            return signature.verify(signatureBytes);
        }
        catch (SignatureException e)
        {
            if (log.isDebugEnabled()) {log.debug("Problem verifying signature: " + e);}
            return false;
        }
    }

    @Override
    public CryptoPrimitive prepareForSign(Key key, ProviderContext providerContext) throws JoseException
    {
        Signature signature = getSignature(providerContext);
        initForSign(signature, key, providerContext);
        return new CryptoPrimitive(signature);
    }

    @Override
    public byte[] sign(CryptoPrimitive cryptoPrimitive, byte[] securedInputBytes) throws JoseException
    {
        Signature signature = cryptoPrimitive.getSignature();
        try
        {
            signature.update(securedInputBytes);
            return signature.sign();
        }
        catch (SignatureException e)
        {
            throw new JoseException("Problem creating signature.", e);
        }
    }

    private void initForSign(Signature signature, Key key, ProviderContext providerContext) throws InvalidKeyException
    {
        try
        {
            PrivateKey privateKey = (PrivateKey) key;
            SecureRandom secureRandom = providerContext.getSecureRandom();
            if (secureRandom == null)
            {
                signature.initSign(privateKey);
            }
            else
            {
                signature.initSign(privateKey, secureRandom);
            }
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new InvalidKeyException(getBadKeyMessage(key) + "for " + getJavaAlgorithm(), e);
        }
    }

    private void initForVerify(Signature signature, Key key) throws InvalidKeyException
    {
        try
        {
           PublicKey publicKey = (PublicKey) key;
           signature.initVerify(publicKey);
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new InvalidKeyException(getBadKeyMessage(key) + "for " + getJavaAlgorithm(), e);
        }
    }

    private String getBadKeyMessage(Key key)
    {
        String msg = key == null ? "key is null" : "algorithm=" + key.getAlgorithm();
        return "The given key (" + msg + ") is not valid ";
    }

    private Signature getSignature(ProviderContext providerContext) throws JoseException
    {
        ProviderContext.Context suppliedKeyProviderContext = providerContext.getSuppliedKeyProviderContext();
        String sigProvider = suppliedKeyProviderContext.getSignatureProvider();
        String javaAlg = getJavaAlgorithm();
        ProviderContext.SignatureAlgorithmOverride algOverride = suppliedKeyProviderContext.getSignatureAlgorithmOverride();
        if (algOverride != null && algOverride.getAlgorithmName() != null)
        {
            javaAlg = algOverride.getAlgorithmName();
        }

        try
        {

            Signature signature = sigProvider == null ? Signature.getInstance(javaAlg) : Signature.getInstance(javaAlg, sigProvider);

            AlgorithmParameterSpec algorithmParameterSpec = this.algorithmParameterSpec;
            if (algOverride != null)
            {
                algorithmParameterSpec = algOverride.getAlgorithmParameterSpec();
            }

            if (algorithmParameterSpec != null)
            {
                try
                {
                    signature.setParameter(algorithmParameterSpec);
                }
                catch (UnsupportedOperationException e)
                {
                    if (log.isDebugEnabled())
                    {
                        log.debug("Unable to set algorithm parameter spec on Signature (java algorithm name: " + javaAlg +
                                ") so ignoring the UnsupportedOperationException and relying on the default parameters.", e);
                    }
                }
            }
            return signature;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Unable to get an implementation of algorithm name: " + javaAlg, e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Invalid algorithm parameter ("+algorithmParameterSpec+") for: " + javaAlg, e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Unable to get an implementation of " + javaAlg + " for provider " + sigProvider, e);
        }
    }

    public abstract void validatePrivateKey(PrivateKey privateKey) throws InvalidKeyException;

    public void validateSigningKey(Key key) throws InvalidKeyException
    {
        checkForNullKey(key);

        try
        {
            validatePrivateKey((PrivateKey)key);
        }
        catch (ClassCastException e)
        {
            throw new InvalidKeyException(getBadKeyMessage(key) + "(not a private key or is the wrong type of key) for "
                    + getJavaAlgorithm() + " / " + getAlgorithmIdentifier() + " " +  e);
        }
    }

    public abstract void validatePublicKey(PublicKey publicKey) throws InvalidKeyException;

    public void validateVerificationKey(Key key) throws InvalidKeyException
    {
        checkForNullKey(key);

        try
        {
            validatePublicKey((PublicKey)key);
        }
        catch (ClassCastException e)
        {
            throw new InvalidKeyException(getBadKeyMessage(key) + "(not a public key or is the wrong type of key) for "
                    + getJavaAlgorithm() + "/" + getAlgorithmIdentifier() + " " +  e);
        }
    }

    private void checkForNullKey(Key key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("Key cannot be null");
        }
    }

    @Override
    public boolean isAvailable()
    {
        try
        {
            Signature signature = getSignature(new ProviderContext());
            return signature != null;
        }
        catch (Exception e)
        {
            log.debug(getAlgorithmIdentifier() + " vai " + getJavaAlgorithm() +
                    " is NOT available from the underlying JCE (" + ExceptionHelp.toStringWithCauses(e) + ").");
            return false;

        }
    }
}
