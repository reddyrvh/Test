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
import org.jose4j.jwt.NumericDate;

import static org.jose4j.lang.Maths.subtract;
import static org.jose4j.lang.Maths.add;


/**
 *
 */
public class NumericDateValidator implements ErrorCodeValidator
{
    private static final Error MISSING_EXP = new Error(ErrorCodes.EXPIRATION_MISSING, "No Expiration Time (exp) claim present.");
    private static final Error MISSING_IAT = new Error(ErrorCodes.ISSUED_AT_MISSING, "No Issued At (iat) claim present.");
    private static final Error MISSING_NBF = new Error(ErrorCodes.NOT_BEFORE_MISSING, "No Not Before (nbf) claim present.");

    private boolean requireExp;
    private boolean requireIat;
    private boolean requireNbf;
    private NumericDate staticEvaluationTime;
    private int allowedClockSkewSeconds = 0;
    private int maxFutureValidityInMinutes = 0;

    private Integer iatAllowedSecondsInTheFuture;
    private Integer iatAllowedSecondsInThePast;

    public void setRequireExp(boolean requireExp)
    {
        this.requireExp = requireExp;
    }

    public void setRequireIat(boolean requireIat)
    {
        this.requireIat = requireIat;
    }

    public void setRequireNbf(boolean requireNbf)
    {
        this.requireNbf = requireNbf;
    }

    public void setEvaluationTime(NumericDate evaluationTime)
    {
        this.staticEvaluationTime = evaluationTime;
    }

    public void setAllowedClockSkewSeconds(int allowedClockSkewSeconds)
    {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    public void setMaxFutureValidityInMinutes(int maxFutureValidityInMinutes)
    {
        this.maxFutureValidityInMinutes = maxFutureValidityInMinutes;
    }

    public void setIatAllowedSecondsInTheFuture(int iatAllowedSecondsInTheFuture)
    {
        this.iatAllowedSecondsInTheFuture = iatAllowedSecondsInTheFuture;
    }

    public void setIatAllowedSecondsInThePast(int iatAllowedSecondsInThePast)
    {
        this.iatAllowedSecondsInThePast = iatAllowedSecondsInThePast;
    }

    @Override
    public Error validate(JwtContext jwtContext) throws MalformedClaimException
    {
        JwtClaims jwtClaims = jwtContext.getJwtClaims();
        NumericDate expirationTime = jwtClaims.getExpirationTime();
        NumericDate issuedAt = jwtClaims.getIssuedAt();
        NumericDate notBefore = jwtClaims.getNotBefore();

        if (requireExp && expirationTime == null)
        {
            return MISSING_EXP;
        }

        if (requireIat && issuedAt == null)
        {
            return MISSING_IAT;
        }

        if (requireNbf && notBefore == null)
        {
            return MISSING_NBF;
        }

        NumericDate evaluationTime = (staticEvaluationTime == null) ? NumericDate.now() : staticEvaluationTime;

        if (expirationTime != null)
        {
            if (subtract(evaluationTime.getValue(), allowedClockSkewSeconds) >= expirationTime.getValue())
            {
                String msg = "The JWT is no longer valid - the evaluation time " + evaluationTime + " is on or after the Expiration Time (exp=" + expirationTime + ") claim value" + skewMessage();
                return new Error(ErrorCodes.EXPIRED, msg);
            }

            if (issuedAt != null && expirationTime.isBefore(issuedAt))
            {
                return new Error(ErrorCodes.MISCELLANEOUS, "The Expiration Time (exp="+expirationTime+") claim value cannot be before the Issued At (iat="+issuedAt+") claim value.");
            }

            if (notBefore != null && expirationTime.isBefore(notBefore))
            {
                return new Error(ErrorCodes.MISCELLANEOUS, "The Expiration Time (exp="+expirationTime+") claim value cannot be before the Not Before (nbf="+notBefore+") claim value.");
            }

            if (maxFutureValidityInMinutes > 0)
            {
                long deltaInSeconds =  subtract(subtract(expirationTime.getValue(), allowedClockSkewSeconds), evaluationTime.getValue());
                if (deltaInSeconds > ((long)maxFutureValidityInMinutes * 60L))
                {
                    String msg = "The Expiration Time (exp="+expirationTime+") claim value cannot be more than " + maxFutureValidityInMinutes
                            + " minutes in the future relative to the evaluation time " + evaluationTime + skewMessage();
                    return new Error(ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE, msg);
                }
            }
        }

        if (notBefore != null)
        {
            if (add(evaluationTime.getValue(), allowedClockSkewSeconds) < notBefore.getValue())
            {
                String msg = "The JWT is not yet valid as the evaluation time " + evaluationTime + " is before the Not Before (nbf=" + notBefore + ") claim time" + skewMessage();
                return new Error(ErrorCodes.NOT_YET_VALID, msg);
            }
        }

        if (issuedAt != null)
        {
            if ((iatAllowedSecondsInTheFuture != null) && (subtract(subtract(issuedAt.getValue(), evaluationTime.getValue()), allowedClockSkewSeconds) > iatAllowedSecondsInTheFuture))
            {
                String msg = "iat " + issuedAt + " is more than " + iatAllowedSecondsInTheFuture + " second(s) ahead of now " + evaluationTime + skewMessage();;
                return new Error(ErrorCodes.ISSUED_AT_INVALID_FUTURE, msg);
            }

            if ((iatAllowedSecondsInThePast != null) && subtract(subtract(evaluationTime.getValue(), issuedAt.getValue()), allowedClockSkewSeconds) > iatAllowedSecondsInThePast)
            {
                String msg = "As of now " + evaluationTime + " iat " + issuedAt + " is more than " + iatAllowedSecondsInThePast + " second(s) in the past" + skewMessage();;
                return new Error(ErrorCodes.ISSUED_AT_INVALID_PAST, msg);
            }
        }

        return null;
    }

    private String skewMessage()
    {
        if (allowedClockSkewSeconds > 0)
        {
            return " (even when providing " + allowedClockSkewSeconds + " seconds of leeway to account for clock skew).";
        }
        else
        {
            return ".";
        }
    }
}
