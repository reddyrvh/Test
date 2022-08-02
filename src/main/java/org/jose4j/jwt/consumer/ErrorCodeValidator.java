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

import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public interface ErrorCodeValidator
{
    /**
     * <p>
     * Validate some aspect of the JWT.
     * </p>
     * <p>
     * Implementations should use negative values
     * for error codes so as to avoid potential collisions with error code values
     * used by this library, which are defined in {@link ErrorCodes}.
     * </p>
     *
     * @param jwtContext the JWT context
     * @return a Error object with a stable error code and description of the problem or null, if valid
     * @throws org.jose4j.jwt.MalformedClaimException if a malformed claim is encountered
     */
    public Error validate(JwtContext jwtContext) throws MalformedClaimException;

    /**
     * JWT validation error with stable error code and friendly error message
     */
    public static class Error
    {
        private int errorCode;
        private String errorMessage;

        /**
         * Creates a new JWT validation error with the given code and message.
         * {@link ErrorCodes} has the codes defined in
         * this library. User defined error codes should use negative values
         * so as to avoid potential collisions with error code values
         * used by this library.
         * @param errorCode the error code
         * @param errorMessage the error message
         */
        public Error(int errorCode, String errorMessage)
        {
            this.errorCode = errorCode;
            this.errorMessage = errorMessage;
        }

        /**
         * The error code. {@link ErrorCodes} has the codes defined in
         * this library.
         * @return the error code
         */
        public int getErrorCode()
        {
            return errorCode;
        }

        /**
         * The error message
         * @return the error message
         */
        public String getErrorMessage()
        {
            return errorMessage;
        }

        @Override
        public String toString()
        {
            return "["+errorCode+"] " + errorMessage;
        }
    }
}
