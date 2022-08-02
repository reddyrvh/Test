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

package org.jose4j.jwt;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.math.BigInteger;
import java.util.*;

/**
 *
 */
public class JwtClaims
{
    private Map<String, Object> claimsMap;
    private String rawJson;

    public JwtClaims()
    {
        claimsMap = new LinkedHashMap<>();
    }

    private JwtClaims(String jsonClaims, JwtContext jwtContext) throws InvalidJwtException
    {
        rawJson = jsonClaims;
        try
        {
            Map<String, Object> parsed = JsonUtil.parseJson(jsonClaims);
            claimsMap = new LinkedHashMap<>(parsed);
        }
        catch (JoseException e)
        {
            String msg = "Unable to parse what was expected to be the JWT Claim Set JSON: \"" + jsonClaims + "\"";
            ErrorCodeValidator.Error error = new ErrorCodeValidator.Error(ErrorCodes.JSON_INVALID, "Invalid JSON.");
            throw new InvalidJwtException(msg, error, e, jwtContext);
        }
    }

    public static JwtClaims parse(String jsonClaims, JwtContext jwtContext) throws InvalidJwtException
    {
        return new JwtClaims(jsonClaims, jwtContext);
    }

    public static JwtClaims parse(String jsonClaims) throws InvalidJwtException
    {
        return new JwtClaims(jsonClaims, null);
    }

    public String getIssuer() throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.ISSUER, String.class);
    }

    public void setIssuer(String issuer)
    {
        claimsMap.put(ReservedClaimNames.ISSUER, issuer);
    }

    public String getSubject()  throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.SUBJECT, String.class);
    }

    public void setSubject(String subject)
    {
        claimsMap.put(ReservedClaimNames.SUBJECT, subject);
    }

    public void setAudience(String audience)
    {
        claimsMap.put(ReservedClaimNames.AUDIENCE, audience);
    }

    public void setAudience(String... audience)
    {
        setAudience(Arrays.asList(audience));
    }

    public void setAudience(List<String> audiences)
    {
        if (audiences.size() == 1)
        {
            setAudience(audiences.get(0));
        }
        else
        {
            claimsMap.put(ReservedClaimNames.AUDIENCE, audiences);
        }
    }

    /**
     * Is there an "aud" (Audience) Claim in this claim set?
     * @return true, if the claims have an "aud" claim, false otherwise
     */
    public boolean hasAudience()
    {
        return hasClaim(ReservedClaimNames.AUDIENCE);
    }

    /**
     * Gets the value of the "aud" (Audience) Claim. An empty list is returned if aud is not present.
     * Use {@link #hasAudience()} to distinguish between an aud claim with an empty array value and
     * the lack of an aud claim.
     * @return a list of the audience values. Will return an empty list, if aud is not present.
     * @throws MalformedClaimException if the value of the audience claim is not an array of strings or a single string value
     */
    public List<String> getAudience() throws MalformedClaimException
    {
        Object audienceObject = claimsMap.get(ReservedClaimNames.AUDIENCE);

        if (audienceObject instanceof String)
        {
            return Collections.singletonList((String) audienceObject);
        }
        else if (audienceObject instanceof List || audienceObject == null)
        {
            List audienceList = (List) audienceObject;
            String claimName = ReservedClaimNames.AUDIENCE;
            return toStringList(audienceList, claimName);
        }

        throw new MalformedClaimException("The value of the '" + ReservedClaimNames.AUDIENCE + "' claim is not an array of strings or a single string value.");
    }

    private List<String> toStringList(List list, String claimName) throws MalformedClaimException
    {
        if (list == null)
        {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>();
        for (Object object : list)
        {
            try
            {
                values.add((String) object);
            }
            catch (ClassCastException e)
            {
                throw new MalformedClaimException("The array value of the '" + claimName + "' claim contains non string values " + classCastMsg(e, object), e);
            }
        }
        return values;
    }

    public NumericDate getExpirationTime() throws MalformedClaimException
    {
        return getNumericDateClaimValue(ReservedClaimNames.EXPIRATION_TIME);
    }

    public void setExpirationTime(NumericDate expirationTime)
    {
        setNumericDateClaim(ReservedClaimNames.EXPIRATION_TIME, expirationTime);
    }

    public void setExpirationTimeMinutesInTheFuture(float minutes)
    {
        setExpirationTime(offsetFromNow(minutes));
    }

    private NumericDate offsetFromNow(float offsetMinutes)
    {
        NumericDate numericDate = NumericDate.now();
        float secondsOffset = offsetMinutes * 60;
        numericDate.addSeconds((long)secondsOffset);
        return numericDate;
    }

    public NumericDate getNotBefore() throws MalformedClaimException
    {
        return getNumericDateClaimValue(ReservedClaimNames.NOT_BEFORE);
    }

    public void setNotBefore(NumericDate notBefore)
    {
        setNumericDateClaim(ReservedClaimNames.NOT_BEFORE, notBefore);
    }

    public void setNotBeforeMinutesInThePast(float minutes)
    {
        setNotBefore(offsetFromNow(-1 * minutes));
    }

    public NumericDate getIssuedAt() throws MalformedClaimException
    {
        return getNumericDateClaimValue(ReservedClaimNames.ISSUED_AT);
    }

    public void setIssuedAt(NumericDate issuedAt)
    {
        setNumericDateClaim(ReservedClaimNames.ISSUED_AT, issuedAt);
    }

    public void setIssuedAtToNow()
    {
        setIssuedAt(NumericDate.now());
    }

    public String getJwtId() throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.JWT_ID, String.class);
    }

    public void setJwtId(String jwtId)
    {
        claimsMap.put(ReservedClaimNames.JWT_ID, jwtId);
    }

    public void setGeneratedJwtId(int numberOfBytes)
    {
        byte[] rndbytes = ByteUtil.randomBytes(numberOfBytes);
        String jti = Base64Url.encode(rndbytes);
        setJwtId(jti);
    }

    public void setGeneratedJwtId()
    {
        setGeneratedJwtId(16);
    }

    public void unsetClaim(String claimName)
    {
        claimsMap.remove(claimName);
    }

    public <T> T getClaimValue(String claimName, Class<T> type) throws MalformedClaimException
    {
        Object o = claimsMap.get(claimName);
        try
        {
            return type.cast(o);
        }
        catch (ClassCastException e)
        {
            throw new MalformedClaimException("The value of the '" + claimName + "' claim is not the expected type " + classCastMsg(e, o), e);
        }
    }

    public Object getClaimValue(String claimName)
    {
        return claimsMap.get(claimName);
    }

    public boolean hasClaim(String claimName)
    {
        return getClaimValue(claimName) != null;
    }

    private String classCastMsg(ClassCastException e, Object o)
    {
        return "(" + o + " - " +e.getMessage() + ")";
    }

    public NumericDate getNumericDateClaimValue(String claimName) throws MalformedClaimException
    {
        Number number = getClaimValue(claimName, Number.class);
        if (number instanceof BigInteger)
        {
            throw new MalformedClaimException(number + " is unreasonable for a NumericDate");
        }
        return number != null ? NumericDate.fromSeconds(number.longValue()) : null;
    }

    public String getStringClaimValue(String claimName) throws MalformedClaimException
    {
        return getClaimValue(claimName, String.class);
    }

    /**
     * Gets the value of the claim, if present, as a string by calling toString on the value returned by
     * {@link #getClaimValue(String)}.
     * @param claimName the claim name
     * @return the claim value as a String or null if no such named claim is present
     */
    public String getClaimValueAsString(String claimName)
    {
        Object claimObjectValue = getClaimValue(claimName);
        return claimObjectValue != null ? claimObjectValue.toString() : null;
    }

    /**
     * Gets the value of the claim as a List of Strings, which assumes that it is a JSON array of strings.
     * @param claimName the name of the claim
     * @return a {@code List<String>} with the values of the claim. Empty list, if the claim is not present.
     * @throws MalformedClaimException if the claim value is not an array or is an array that contains non string values
     */
    public List<String> getStringListClaimValue(String claimName) throws MalformedClaimException
    {
        List listClaimValue = getClaimValue(claimName, List.class);
        return toStringList(listClaimValue, claimName);
    }

    public void setNumericDateClaim(String claimName, NumericDate value)
    {
        claimsMap.put(claimName, value != null ? value.getValue() : null);
    }

    public void setStringClaim(String claimName, String value)
    {
        claimsMap.put(claimName, value);
    }

    public void setStringListClaim(String claimName, List<String> values)
    {
        claimsMap.put(claimName, values);
    }

    public void setStringListClaim(String claimName, String... values)
    {
        claimsMap.put(claimName, Arrays.asList(values));
    }

    public void setClaim(String claimName, Object value)
    {
        claimsMap.put(claimName, value);
    }

    public boolean isClaimValueOfType(String claimName, Class type)
    {
        try
        {
            return getClaimValue(claimName, type) != null;
        }
        catch (MalformedClaimException e)
        {
            return false;
        }
    }

    public boolean isClaimValueString(String claimName)
    {
        return isClaimValueOfType(claimName, String.class);
    }

    /**
     * Is the claim present with a string array value.
     * @param claimName the name of the claim
     * @return true, if the claim is present and its value is array of strings. False otherwise.
     */
    public boolean isClaimValueStringList(String claimName)
    {
        try
        {
            return hasClaim(claimName) && getStringListClaimValue(claimName) != null;
        }
        catch (MalformedClaimException e)
        {
            return false;
        }
    }

    public Map<String,List<Object>> flattenClaims()
    {
        return flattenClaims(null);
    }

    public Map<String,List<Object>> flattenClaims(Set<String> omittedClaims)
    {
        omittedClaims = omittedClaims == null ? Collections.<String>emptySet() : omittedClaims;
        Map<String,List<Object>> flattenedClaims = new LinkedHashMap<>();
        for (Map.Entry<String,Object> e : claimsMap.entrySet())
        {
            final String key = e.getKey();
            if (!omittedClaims.contains(key))
            {
                dfs(null, key, e.getValue(), flattenedClaims);
            }
        }
        return flattenedClaims;
    }

    private void dfs(String baseName, String name, Object value, Map<String,List<Object>> flattenedClaims)
    {
        String key = (baseName == null ? "" : baseName + ".") + name;
        if (value instanceof List)
        {
            List<Object> newList = new ArrayList<>();
            for (Object item : (List)value)
            {
                if (item instanceof Map)
                {
                    Map<?,?> mv = (Map<?,?>) item;
                    for (Map.Entry<?,?> e : mv.entrySet())
                    {
                        dfs(key, e.getKey().toString(), e.getValue(), flattenedClaims);
                    }
                }
                else
                {
                    newList.add(item);
                }
            }
            flattenedClaims.put(key, newList);
        }
        else if (value instanceof Map)
        {
            Map<?,?> mapValue = (Map<?,?>) value;
            for (Map.Entry<?,?> e : mapValue.entrySet())
            {
                dfs(key, e.getKey().toString(), e.getValue(), flattenedClaims);
            }
        }
        else
        {
            flattenedClaims.put(key, Collections.singletonList(value));
        }
    }


    public Map<String, Object> getClaimsMap(Set<String> omittedClaims)
    {
        omittedClaims = (omittedClaims != null) ? omittedClaims : Collections.<String>emptySet();
        LinkedHashMap<String, Object>  claims = new LinkedHashMap<>(claimsMap);
        for (String omittedClaim : omittedClaims)
        {
            claims.remove(omittedClaim);
        }

        return claims;
    }

    public Map<String, Object> getClaimsMap()
    {
        return getClaimsMap(null);
    }

    public Collection<String> getClaimNames(Set<String> omittedClaims)
    {
        return getClaimsMap(omittedClaims).keySet();
    }

    public Collection<String> getClaimNames()
    {
        return getClaimNames(null);
    }

    public String toJson()
    {
        return JsonUtil.toJson(claimsMap);
    }

    public String getRawJson()
    {
        return rawJson;
    }

    @Override
    public String toString()
    {
        return "JWT Claims Set:" + claimsMap;
    }
}
