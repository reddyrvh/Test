/*
 * Copyright 2012-2021 Brian Campbell
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
package org.jose4j.jwe.kdf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ConcatKeyDerivationFunctionFactory
{
    private final static Logger log = LoggerFactory.getLogger(ConcatKeyDerivationFunctionFactory.class);

    private static Class<ConcatenationKeyDerivationFunctionWithSha256> customKdfClass;

    static
    {
        String name = System.getProperty("org.jose4j.jwe.kdf.ConcatenationKeyDerivationFunctionWithSha256");
        if (name != null)
        {
            try
            {
                customKdfClass = (Class<ConcatenationKeyDerivationFunctionWithSha256>)Class.forName(name);
                ConcatenationKeyDerivationFunctionWithSha256 kdf = customKdfClass.newInstance();
                byte[] z = new byte[] {124, -81, 43, 14, -71, -72, -84, 75, 115, 73, -52, -39, 74, -58, 77, -83};
                kdf.kdf(z, 512, new byte[8]);
                log.debug("Using custom ConcatenationKeyDerivationFunctionWithSha256 implementation: " + kdf.getClass());
            }
            catch (Throwable e)
            {
                customKdfClass = null;
                log.debug("Using jose4j's concatenation key derivation function implementation because of problems with " + name, e);
            }
        }
    }

    static ConcatenationKeyDerivationFunctionWithSha256 make(String provider)
    {
        if (customKdfClass != null)
        {
            try
            {
                return customKdfClass.newInstance();
            }
            catch (Exception e)
            {
                log.debug("Unable to create new instance of " + customKdfClass, e);
            }
        }

        return new ConcatKeyDerivationFunction("SHA-256", provider);
    }
}
