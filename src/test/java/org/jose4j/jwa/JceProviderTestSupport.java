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

package org.jose4j.jwa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwe.ContentEncryptionAlgorithm;
import org.jose4j.jwe.KeyManagementAlgorithm;
import org.jose4j.jws.JsonWebSignatureAlgorithm;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class JceProviderTestSupport
{
    private boolean putBouncyCastleFirst = true;
    private boolean useBouncyCastleRegardlessOfAlgs;
    private boolean doReinitialize = true;
    private boolean useLegacyPssNames = false;
    private Set<String> signatureAlgs = Collections.emptySet();
    private Set<String> keyManagementAlgs = Collections.emptySet();
    private Set<String> encryptionAlgs = Collections.emptySet();

    private void reinitialize()
    {
        AlgorithmFactoryFactory.getInstance().reinitialize();
    }

    public void runWithBouncyCastleProviderIfNeeded(RunnableTest test) throws Exception
    {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        boolean needBouncyCastle = useBouncyCastleRegardlessOfAlgs;

        AlgorithmFactoryFactory aff = AlgorithmFactoryFactory.getInstance();

        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = aff.getJwsAlgorithmFactory();
        if (!jwsAlgorithmFactory.getSupportedAlgorithms().containsAll(signatureAlgs))
        {
            needBouncyCastle = true;
        }

        AlgorithmFactory<KeyManagementAlgorithm> jweKeyMgmtAlgorithmFactory = aff.getJweKeyManagementAlgorithmFactory();
        if (!jweKeyMgmtAlgorithmFactory.getSupportedAlgorithms().containsAll(keyManagementAlgs))
        {
            needBouncyCastle = true;
        }

        AlgorithmFactory<ContentEncryptionAlgorithm> jweEncAlgFactory = aff.getJweContentEncryptionAlgorithmFactory();
        if (!jweEncAlgFactory.getSupportedAlgorithms().containsAll(encryptionAlgs))
        {
            needBouncyCastle = true;
        }

        if (useLegacyPssNames)
        {
            System.setProperty("org.jose4j.jws.use-legacy-rsapss-alg-names", "true");
        }

        boolean removeBouncyCastle = true;
        try
        {
            if (needBouncyCastle)
            {
                final int targetPosition = putBouncyCastleFirst ? 1 : Security.getProviders().length + 1;
                int position = Security.insertProviderAt(bouncyCastleProvider, targetPosition);
                removeBouncyCastle = (position != -1);
                if (doReinitialize)
                {
                    reinitialize();
                }
            }

            test.runTest();
        }
        finally
        {
            if (needBouncyCastle || useLegacyPssNames)
            {
                if (useLegacyPssNames)
                {
                    System.clearProperty("org.jose4j.jws.use-legacy-rsapss-alg-names");
                }

                if (removeBouncyCastle)
                {
                    Security.removeProvider(bouncyCastleProvider.getName());
                }

                if (doReinitialize)
                {
                    reinitialize();
                }
            }
        }
    }

    public void setSignatureAlgsNeeded(String... algs)
    {
        signatureAlgs = new HashSet<>(Arrays.asList(algs));
    }

    public void setKeyManagementAlgsNeeded(String... algs)
    {
        keyManagementAlgs = new HashSet<>(Arrays.asList(algs));
    }

    public void setEncryptionAlgsNeeded(String... algs)
    {
        encryptionAlgs = new HashSet<>(Arrays.asList(algs));
    }

    public void setDoReinitialize(boolean doReinitialize)
    {
        this.doReinitialize = doReinitialize;
    }

    public void setUseLegacyPssNames(boolean useLegacyPssNames)
    {
        this.useLegacyPssNames = useLegacyPssNames;
    }

    public void setUseBouncyCastleRegardlessOfAlgs(boolean useBouncyCastleRegardlessOfAlgs)
    {
        this.useBouncyCastleRegardlessOfAlgs = useBouncyCastleRegardlessOfAlgs;
    }

    public void setPutBouncyCastleFirst(boolean putBouncyCastleFirst)
    {
        this.putBouncyCastleFirst = putBouncyCastleFirst;
    }

    public static interface RunnableTest
    {
        public abstract void runTest() throws Exception;
    }
}
