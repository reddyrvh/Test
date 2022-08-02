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

package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.util.List;
import java.util.Set;

/**
 * Validate the "aud" (Audience) Claim per http://tools.ietf.org/html/rfc7519#section-4.1.3
 */
public class AudValidator implements ErrorCodeValidator
{
    private static final Error MISSING_AUD = new Error(ErrorCodes.AUDIENCE_MISSING, "No Audience (aud) claim present.");

    private Set<String> acceptableAudiences;
    private boolean requireAudience;

    public AudValidator(Set<String> acceptableAudiences, boolean requireAudience)
    {
        this.acceptableAudiences = acceptableAudiences;
        this.requireAudience = requireAudience;
    }

    @Override
    public Error validate(JwtContext jwtContext) throws MalformedClaimException
    {
        final JwtClaims jwtClaims = jwtContext.getJwtClaims();

        if (!jwtClaims.hasAudience())
        {
            return requireAudience ? MISSING_AUD : null;
        }

        List<String> audiences = jwtClaims.getAudience();

        boolean ok = false;
        for (String audience : audiences)
        {
            if (acceptableAudiences.contains(audience))
            {
                ok = true;
            }
        }

        if (!ok)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Audience (aud) claim " ).append(audiences);
            if (acceptableAudiences.isEmpty())
            {
                sb.append(" present in the JWT but no expected audience value(s) were provided to the JWT Consumer.");
            }
            else
            {
                sb.append(" doesn't contain an acceptable identifier.");
            }
            sb.append(" Expected ");
            if (acceptableAudiences.size() == 1)
            {
                sb.append(acceptableAudiences.iterator().next());
            }
            else
            {
                sb.append("one of ").append(acceptableAudiences);
            }
            sb.append(" as an aud value.");

            return new Error(ErrorCodes.AUDIENCE_INVALID, sb.toString());
        }

        return null;
    }
}
