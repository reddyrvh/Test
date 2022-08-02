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
package org.jose4j.jca;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Allows for the caller of various JOSE and JWT functionality to specify
 * a particular Java Cryptography Architecture provider by name for various
 * cryptographic operations as well as a {@code SecureRandom} source of randomness.
 * <p>
 * Use {@link #getSuppliedKeyProviderContext()} to indicate the provider to be used for cryptographic operations
 * directly involve the key supplied by the caller.
 * Use {@link #getGeneralProviderContext()}
 * to indicate the provider to be used for other operations that do not directly involve the key supplied by the caller.
 * Signing and verification are operations that use the supplied key as do
 * key encryption and key agreement methods used to transmit or arrive at the content encryption key. Content encryption, however,
 * is done with that content encryption key rather than the supplied key. So, other than when using direct (alg=dir) encryption,
 * set the cipher provider name on the general provider to control the provider used in content encryption.
 * For example, to specify the provider for an RSA signature when producing a JWS, create a new {@code ProviderContext} and set the name of the provider using
 * {@link org.jose4j.jca.ProviderContext.Context#setSignatureProvider(String)} on the {@link Context} obtained from calling
 * {@link #getSuppliedKeyProviderContext()}. To specify the provider for an HMAC when producing a JWS, set the name of the provider using
 * {@link org.jose4j.jca.ProviderContext.Context#setMacProvider(String)} on the {@code Context} obtained from calling {@code getSuppliedKeyProviderContext()}.
 * To specify the provider for decrypting a key with RSA when consuming a JWE, use {@link org.jose4j.jca.ProviderContext.Context#setCipherProvider(String)}
 * on the Context obtained from {@code getSuppliedKeyProviderContext()}. To specify the provider for decrypting the content of the message, on the other hand,
 * set the cipher provider on the Context obtained from {@code getGeneralProviderContext()}.
 * <p>
 * A ProviderContext can be set on a {@link org.jose4j.jws.JsonWebSignature} or {@link org.jose4j.jwe.JsonWebEncryption} as well as a
 * {@link org.jose4j.jwt.consumer.JwtConsumer} via the {@link org.jose4j.jwt.consumer.JwtConsumerBuilder}.
 *
 *
 * @see org.jose4j.jwx.JsonWebStructure#setProviderContext(ProviderContext)
 * @see org.jose4j.jwt.consumer.JwtConsumerBuilder#setJwsProviderContext(ProviderContext)
 * @see org.jose4j.jwt.consumer.JwtConsumerBuilder#setJweProviderContext(ProviderContext)
 */
public class ProviderContext
{
    private SecureRandom secureRandom;
    private Context suppliedKeyProviderContext = new Context();
    private Context generalProviderContext = new Context();

    /**
     * The Java Cryptography Architecture provider context to be used for operations
     * that directly involve the key supplied by the caller.
     * @return the {@code Context} object on which various provider preferences can be set
     */
    public Context getSuppliedKeyProviderContext()
    {
        return suppliedKeyProviderContext;
    }

    /**
     * The Java Cryptography Architecture provider context to be used for operations
     * that do not directly involve the key supplied by the caller.
     * @return the {@code Context} object on which various provider preferences can be set
     */
    public Context getGeneralProviderContext()
    {
        return generalProviderContext;
    }

    /**
     * Gets the secure random generator.
     *
     * @return The specific secure random generator if set, otherwise
     *         {@code null} for a default system one.
     */
    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }

    /**
     * Sets the secure random generator.
     *
     * @param secureRandom the SecureRandom to use or {@code null} for a default system one.
     */
    public void setSecureRandom(SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
    }

    /**
     * Allows for a provider to be named for various operations.
     * Not all operations are relevant in any particular JOSE context.
     */
    public class Context
    {
        private String generalProvider;

        private String keyPairGeneratorProvider;
        private String keyAgreementProvider;
        private String cipherProvider;
        private String signatureProvider;
        private SignatureAlgorithmOverride signatureAlgorithmOverride;
        private String macProvider;
        private String messageDigestProvider;
        private String keyFactoryProvider;

        /**
         *  Gets the general JCA provider to be used for all relevant operations when
         *  a more specific one isn't set.
         * @return the general JCA provider name
         */
        public String getGeneralProvider()
        {
            return generalProvider;
        }

        /**
         *  Sets the general JCA provider to be used for all relevant operations when
         *  a more specific one isn't set. {@code null} to use the system configured
         *  providers.
         *
         * @param generalProvider the provider name
         */
        public void setGeneralProvider(String generalProvider)
        {
            this.generalProvider = generalProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code KeyPairGenerator} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getKeyPairGeneratorProvider()
        {
            return select(keyPairGeneratorProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code KeyPairGenerator} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param keyPairGeneratorProvider  the provider name
         */
        public void setKeyPairGeneratorProvider(String keyPairGeneratorProvider)
        {
            this.keyPairGeneratorProvider = keyPairGeneratorProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code KeyAgreement} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getKeyAgreementProvider()
        {
            return select(keyAgreementProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code KeyAgreement} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param keyAgreementProvider  the provider name
         */
        public void setKeyAgreementProvider(String keyAgreementProvider)
        {
            this.keyAgreementProvider = keyAgreementProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code Cipher} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getCipherProvider()
        {
            return select(cipherProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code Cipher} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param cipherProvider  the provider name
         */
        public void setCipherProvider(String cipherProvider)
        {
            this.cipherProvider = cipherProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code Signature} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getSignatureProvider()
        {
            return select(signatureProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code Signature} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param signatureProvider the provider name
         */
        public void setSignatureProvider(String signatureProvider)
        {
            this.signatureProvider = signatureProvider;
        }

        /**
         * Gets the the algorithm info (name and parameter spec) to be used as overrides for relevant {@code Signature} operations.
         * Null means no override is done and the normal algorithm details are used.
         * @return the SignatureAlgorithmOverride object or null
         */
        public SignatureAlgorithmOverride getSignatureAlgorithmOverride()
        {
            return signatureAlgorithmOverride;
        }

        /**
         * Sets the algorithm info (name and parameter spec) to be used as overrides for relevant {@code Signature} operations.
         * The need for this should be quite rare but it could be useful in cases where different providers are using different
         * names for the same algorithm - and there have been some naming inconsistencies with RSAPSS where RSASSA-PSS + AlgorithmParameterSpec
         * was used when PSS support was added to the default JRE but providers that supported PSS earlier used something like SHA256withRSAandMGF1).
         *
         * @param signatureAlgorithmOverride with the algorithm info. Null indicates to use the defaults (and is the default in and of itself).
         */
        public void setSignatureAlgorithmOverride(SignatureAlgorithmOverride signatureAlgorithmOverride)
        {
            this.signatureAlgorithmOverride = signatureAlgorithmOverride;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code Mac} operations.
         * @return of the Mac provider or {@code null} for the the system configured providers.
         */
        public String getMacProvider()
        {
            return select(macProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code Mac} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param macProvider the provider name
         */
        public void setMacProvider(String macProvider)
        {
            this.macProvider = macProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code MessageDigest} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getMessageDigestProvider()
        {
            return select(messageDigestProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code MessageDigest} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param messageDigestProvider the provider name
         */
        public void setMessageDigestProvider(String messageDigestProvider)
        {
            this.messageDigestProvider = messageDigestProvider;
        }

        /**
         * Gets the the JCA provider to be used for relevant {@code KeyFactory} operations.
         * @return the name of the provider or {@code null} for the the system configured providers.
         */
        public String getKeyFactoryProvider()
        {
            return select(keyFactoryProvider);
        }

        /**
         *  Sets the the JCA provider to be used for relevant {@code KeyFactory} operations.
         *  {@code null} to use the system configured providers.
         *
         * @param keyFactoryProvider the provider name
         */
        public void setKeyFactoryProvider(String keyFactoryProvider)
        {
            this.keyFactoryProvider = keyFactoryProvider;
        }

        private String select(String specificValue)
        {
            return specificValue == null ? generalProvider : specificValue;
        }
    }

    /**
     * Signature Algorithm info used to override normal defaults.
     */
    public static class SignatureAlgorithmOverride
    {
        private String algorithmName;
        private AlgorithmParameterSpec AlgorithmParameterSpec;

        /**
         * Create a new SignatureAlgorithmOverride instance
         * @param algorithmName the algorithm name (e.g. SHA256withRSAandMGF1)
         * @param aps the AlgorithmParameterSpec
         */
        public SignatureAlgorithmOverride(String algorithmName, AlgorithmParameterSpec aps)
        {
            this.algorithmName = algorithmName;
            AlgorithmParameterSpec = aps;
        }

        /**
         * Gets the name of the signature algorithm to use in place of the normal default one.
         * @return the signature algorithm name.
         */
        public String getAlgorithmName()
        {
            return algorithmName;
        }

        /**
         * Gets the AlgorithmParameterSpec to use in place of the normal default one.
         * @return the AlgorithmParameterSpec.
         */
        public AlgorithmParameterSpec getAlgorithmParameterSpec()
        {
            return AlgorithmParameterSpec;
        }
    }

}
