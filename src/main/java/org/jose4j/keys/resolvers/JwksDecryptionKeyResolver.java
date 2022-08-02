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
package org.jose4j.keys.resolvers;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.DecryptionJwkSelector;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import java.security.Key;
import java.util.List;

/**
 *
 */
public class JwksDecryptionKeyResolver implements DecryptionKeyResolver
{
    private final List<JsonWebKey> jsonWebKeys;
    private final DecryptionJwkSelector selector = new DecryptionJwkSelector();
    boolean disambiguateWithAttemptDecrypt;

    public JwksDecryptionKeyResolver(List<JsonWebKey> jsonWebKeys)
    {
        this.jsonWebKeys = jsonWebKeys;
    }

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
    {
        JsonWebKey selected;
        try
        {
            List<JsonWebKey> selectedList = selector.selectList(jwe, this.jsonWebKeys);
            if (selectedList.isEmpty())
            {
                selected = null;
            }
            else if (selectedList.size() == 1 || !disambiguateWithAttemptDecrypt)
            {
                selected = selectedList.get(0);
            }
            else
            {
                selected = selector.attemptDecryptDisambiguate(jwe, selectedList);
                if (selected == null)
                {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Unable to find a suitable key for JWE w/ header ").append(jwe.getHeaders().getFullHeaderAsJsonString());
                    sb.append(" using attempted decryption to disambiguate from filtered candidate JWKs ").append(jsonWebKeys);
                    throw new UnresolvableKeyException(sb.toString());
                }
            }
        }
        catch (JoseException e)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable key for JWE w/ header ").append(jwe.getHeaders().getFullHeaderAsJsonString());
            sb.append(" due to an unexpected exception (").append(e).append(") selecting from keys: ").append(jsonWebKeys);
            throw new UnresolvableKeyException(sb.toString(), e);
        }

        if (selected == null)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable key for JWE w/ header ").append(jwe.getHeaders().getFullHeaderAsJsonString());
            sb.append(" from JWKs ").append(jsonWebKeys);
            throw new UnresolvableKeyException(sb.toString());
        }

        return selected instanceof PublicJsonWebKey ? ((PublicJsonWebKey) selected).getPrivateKey() : selected.getKey();
    }

    /**
     * Indicates whether to try decrypting to disambiguate when the normal key selection based on the JWE headers results in more than one key. Default is false.
     * @param disambiguateWithAttemptDecrypt boolean indicating whether to use decrypting to disambiguate
     */
    public void setDisambiguateWithAttemptDecrypt(boolean disambiguateWithAttemptDecrypt)
    {
        this.disambiguateWithAttemptDecrypt = disambiguateWithAttemptDecrypt;
    }
}
