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

package org.jose4j.json;

import org.jose4j.lang.JoseException;
import java.util.Map;

/**
 * @deprecated as of 0.3.7 please use JsonUtil
 *
 */
public class JsonHeaderUtil
{
    /**
     * @deprecated please use JsonUtil
     * @param jsonString Sting
     * @return Map
     * @throws JoseException JoseException
     */
    public static Map<String,Object> parseJson(String jsonString) throws JoseException
    {
        return JsonUtil.parseJson(jsonString);
    }

    /**
     * @deprecated please use JsonUtil
     * @param map Map
     * @return String
     */
    public static String toJson(Map<String,?> map)
    {
        return JsonUtil.toJson(map);
    }
}
