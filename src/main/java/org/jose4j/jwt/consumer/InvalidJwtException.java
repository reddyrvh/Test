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

import java.util.Collections;
import java.util.List;

/**
 * An exception thrown when a JWT is considered invalid or otherwise cannot be
 * processed/consumed.
 */
public class InvalidJwtException extends Exception
{
    private List<ErrorCodeValidator.Error> details = Collections.emptyList();
    private JwtContext jwtContext;

    public InvalidJwtException(String message, List<ErrorCodeValidator.Error> details, JwtContext jwtContext)
    {
        super(message);
        this.details = details;
        this.jwtContext = jwtContext;
    }

    public InvalidJwtException(String message, ErrorCodeValidator.Error detail, Throwable cause, JwtContext jwtContext)
    {
        super(message, cause);
        this.jwtContext = jwtContext;
        details = Collections.singletonList(detail);
    }

    /**
     * <p>
     * Provides programmatic access to (some) specific reasons for JWT invalidity
     * by indicating if the given error code was one of the reasons for the
     * JWT being considered invalid.
     * </p>
     * <p>
     * Error codes used by this library are defined in {@link ErrorCodes}.
     * </p>
     * @param code the given error code
     * @return true if the given error code was one of the reasons for the JWT being invalid and false otherwise
     */
    public boolean hasErrorCode(int code)
    {
        for (ErrorCodeValidator.Error error : details)
        {
            if (code == error.getErrorCode())
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Indicates if the JWT was invalid because it had expired
     * (i.e. the expiration time "exp" claim identified a time in the past).
     * This is equivalent to calling
     * <code>hasErrorCode(ErrorCodes.EXPIRED)</code>
     * @return true if expiration is one of the reasons for the JWT being invalid and false otherwise
     */
    public boolean hasExpired()
    {
        return hasErrorCode(ErrorCodes.EXPIRED);
    }

    /**
     * Returns a list of reasons the JWT was considered invalid.
     * @return the list of error reasons/details
     */
    public List<ErrorCodeValidator.Error> getErrorDetails()
    {
        return details;
    }

    /**
     * Returns a <code>JwtContext</code> object including the <code>JwtClaims</code>
     * representing the JWT processed
     * up to the point of this <code>InvalidJwtException</code> being thrown.
     * Some care should be taken when using this because, depending on what kind
     * of error was encountered in processing the JWT and
     * when it was encountered, the <code>JwtContext</code> may not be complete.
     * @return the <code>JwtContext</code>
     */
    public JwtContext getJwtContext()
    {
        return jwtContext;
    }

    @Override
    public String getMessage()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(super.getMessage());
        if (!details.isEmpty())
        {
            sb.append(" Additional details: ");
            sb.append(details);
        }
        return sb.toString();
    }

    /**
     * Returns the original message of this exception without the details.
     * @return the original message
     */
    public String getOriginalMessage() {
        return super.getMessage();
    }
}
