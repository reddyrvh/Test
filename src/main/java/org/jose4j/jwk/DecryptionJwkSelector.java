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

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.Collection;
import java.util.List;

/**
 *
 */
public class DecryptionJwkSelector
{
    private static final Logger log = LoggerFactory.getLogger(DecryptionJwkSelector.class);

    public JsonWebKey select(JsonWebEncryption jwe, Collection<JsonWebKey> keys) throws JoseException
    {
        List<JsonWebKey> jsonWebKeys = selectList(jwe, keys);
        return jsonWebKeys.isEmpty() ? null : jsonWebKeys.get(0);
    }

    public List<JsonWebKey> selectList(JsonWebEncryption jwe, Collection<JsonWebKey> keys) throws JoseException
    {
        SimpleJwkFilter filter = SelectorSupport.filterForInboundEncrypted(jwe);
        return filter.filter(keys);
    }

    public JsonWebKey attemptDecryptDisambiguate(JsonWebEncryption jwe, List<JsonWebKey> jsonWebKeys)
    {
        for (JsonWebKey jwk : jsonWebKeys)
        {
            Key key;
            if (jwk instanceof PublicJsonWebKey)
            {
                PublicJsonWebKey publicJwk = (PublicJsonWebKey) jwk;
                key = publicJwk.getPrivateKey();
            }
            else
            {
                key = jwk.getKey();
            }

            if (key != null)
            {
                jwe.setKey(key);
                try {
                    byte[] plaintextBytes = jwe.getPlaintextBytes();
                    if (plaintextBytes != null)
                    {
                        return jwk;
                    }
                }
                catch (JoseException e)
                {
                    log.debug("Not using key (kid={}) b/c attempt to decrypt failed trying to disambiguate ({}).", jwk.getKeyId(), ExceptionHelp.toStringWithCauses(e));
                }
            }
        }

        return null;
    }
}
