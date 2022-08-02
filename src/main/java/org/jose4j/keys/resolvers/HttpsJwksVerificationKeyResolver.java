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

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Key;
import java.util.List;

/**
 *
 */
public class HttpsJwksVerificationKeyResolver implements VerificationKeyResolver
{
    private static final Logger log = LoggerFactory.getLogger(HttpsJwksVerificationKeyResolver.class);

    private VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();

    private HttpsJwks httpsJkws;

    private boolean disambiguateWithVerifySignature;

    public HttpsJwksVerificationKeyResolver(HttpsJwks httpsJkws)
    {
        this.httpsJkws = httpsJkws;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
    {
        JsonWebKey theChosenOne;
        List<JsonWebKey> jsonWebKeys;

        try
        {
            jsonWebKeys = httpsJkws.getJsonWebKeys();

            theChosenOne = select(jws, jsonWebKeys);
            if (theChosenOne == null)
            {
                log.debug("Refreshing JWKs from {} as no suitable verification key for JWS w/ header {} was found in {}", httpsJkws.getLocation(), jws.getHeaders().getFullHeaderAsJsonString(), jsonWebKeys);

                httpsJkws.refresh();
                jsonWebKeys = httpsJkws.getJsonWebKeys();
                theChosenOne = select(jws, jsonWebKeys);
            }
        }
        catch (JoseException | IOException e)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable verification key for JWS w/ header ").append(jws.getHeaders().getFullHeaderAsJsonString());
            sb.append(" due to an unexpected exception (").append(e).append(") while obtaining or using keys from JWKS endpoint at ").append(httpsJkws.getLocation());
            throw new UnresolvableKeyException(sb.toString(), e);
        }

        if (theChosenOne == null)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable verification key for JWS w/ header ").append(jws.getHeaders().getFullHeaderAsJsonString());
            sb.append(" from JWKs ").append(jsonWebKeys).append(" obtained from ").append(httpsJkws.getLocation());
            throw new UnresolvableKeyException(sb.toString());
        }

        return theChosenOne.getKey();
    }

    protected JsonWebKey select(JsonWebSignature jws, List<JsonWebKey> jsonWebKeys) throws JoseException
    {
        if (disambiguateWithVerifySignature)
        {
            return verificationJwkSelector.selectWithVerifySignatureDisambiguate(jws, jsonWebKeys);
        }
        else
        {
            return verificationJwkSelector.select(jws, jsonWebKeys);
        }
    }

    /**
     * Indicates whether or not to use signature verification to try and disambiguate when the normal key selection based on the JWS headers results in more than one key. Default is false.
     * @param disambiguateWithVerifySignature boolean indicating whether or not to use signature verification to disambiguate
     */
    public void setDisambiguateWithVerifySignature(boolean disambiguateWithVerifySignature)
    {
        this.disambiguateWithVerifySignature = disambiguateWithVerifySignature;
    }
}
