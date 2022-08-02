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
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 */
public class JsonWebKeySet
{
    private static final Logger log = LoggerFactory.getLogger(JsonWebKeySet.class);

    public static final String JWK_SET_MEMBER_NAME = "keys";

    private List<JsonWebKey> keys;

    public JsonWebKeySet(String json) throws JoseException
    {
        Map<String,Object> parsed = JsonUtil.parseJson(json);
        List<Map<String,Object>> jwkParamMapList = (List<Map<String,Object>>) parsed.get(JWK_SET_MEMBER_NAME);

        if (jwkParamMapList == null)
        {
            throw new JoseException("The JSON JWKS content does not include the " + JWK_SET_MEMBER_NAME + " member.");
        }

        keys = new ArrayList<>(jwkParamMapList.size());
        for (Map<String,Object> jwkParamsMap : jwkParamMapList)
        {
            try
            {
                JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkParamsMap);
                keys.add(jwk);
            }
            catch (Exception e)
            {
                log.debug("Ignoring an individual JWK in a JWKS due to a problem processing it. JWK params: {} and the full JWKS content: {}. {}", jwkParamsMap, json, e);
            }
        }
    }

    public JsonWebKeySet(JsonWebKey... keys)
    {
        this(Arrays.asList(keys));
    }

    public JsonWebKeySet(List<? extends JsonWebKey> keys)
    {
        this.keys = new ArrayList<>(keys.size());
        for (JsonWebKey jwk : keys)
        {
            this.keys.add(jwk);
        }
    }

    public void addJsonWebKey(JsonWebKey jsonWebKey)
    {
        keys.add(jsonWebKey);
    }

    public List<JsonWebKey> getJsonWebKeys()
    {
        return keys;
    }

    public JsonWebKey findJsonWebKey(String keyId, String keyType, String use, String algorithm)
    {
        List<JsonWebKey> found = findJsonWebKeys(keyId, keyType, use, algorithm);
        return found.isEmpty() ? null : found.iterator().next();
    }

    public List<JsonWebKey> findJsonWebKeys(String keyId, String keyType, String use, String algorithm)
    {
        List<JsonWebKey> found = new ArrayList<JsonWebKey>();
        for (JsonWebKey jwk : keys)
        {
            boolean isMeetsCriteria = true;

            if (keyId != null)
            {
                isMeetsCriteria = keyId.equals(jwk.getKeyId());
            }

            if (use != null)
            {
                isMeetsCriteria &= use.equals(jwk.getUse());
            }

            if (keyType != null)
            {
                isMeetsCriteria &= keyType.equals(jwk.getKeyType());
            }

            if (algorithm != null)
            {
                isMeetsCriteria &= algorithm.equals(jwk.getAlgorithm());
            }

            if (isMeetsCriteria)
            {
                found.add(jwk);
            }
        }
        return found;
    }

    public String toJson()
    {
        return toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
    }

    public String toJson(JsonWebKey.OutputControlLevel outputControlLevel)
    {
        List<Map<String, Object>> keyList = new ArrayList<>(keys.size());

        for (JsonWebKey key : keys)
        {
            Map<String, Object> params = key.toParams(outputControlLevel);
            keyList.add(params);
        }

        Map<String,Object> jwks = new LinkedHashMap<String,Object>();
        jwks.put(JWK_SET_MEMBER_NAME, keyList);
        return JsonUtil.toJson(jwks);
    }
}
