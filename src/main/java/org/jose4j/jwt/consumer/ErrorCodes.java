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

/**
 * <p>
 * Error codes, as <code>int</code> values, used by this library for
 * programmatic access to (some) specific reasons for JWT invalidity
 * by using {@link InvalidJwtException#hasErrorCode(int)}.
 * </p>
 *
 * <p>
 * New error code values may be added and used in future versions but only nonnegative values will be utilized.
 * Thus custom ErrorCodeValidator implementations should use negative values
 * for error codes so as to avoid potential collisions with error code values
 * used by this library.
 * </p>
 */
public class ErrorCodes
{
    /**
     * The JWT expired (i.e. the Expiration Time "exp" claim identified a time in the past).
     */
    public static final int EXPIRED = 1;

    /**
     * The JWT had no Expiration Time "exp" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int EXPIRATION_MISSING = 2;

    /**
     * The JWT had no Issued At "iat" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int ISSUED_AT_MISSING = 3;

    /**
     * The JWT had no Not Before "nbf" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int NOT_BEFORE_MISSING = 4;

    /**
     * The JWT had an Expiration Time "exp" claim with a value that was too far
     * in the future based on the set up of the <code>JwtConsumer</code>.
     */
    public static final int EXPIRATION_TOO_FAR_IN_FUTURE = 5;

    /**
     * The Not Before "nbf" claim of the JWT indicates that it is not yet valid.
     */
    public static final int NOT_YET_VALID = 6;

    /**
     * The JWT had no Audience "aud" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int AUDIENCE_MISSING = 7;

    /**
     * The Audience "aud" claim was invalid based on the audience that the <code>JwtConsumer</code>
     * was set up to expect.
     */
    public static final int AUDIENCE_INVALID = 8;

    /**
     * The JWS signature was not successfully verified with the given/resolved key.
     */
    public static final int SIGNATURE_INVALID = 9;

    /**
     * No JWS signature was present but the <code>JwtConsumer</code> was
     * set up to require one.
     */
    public static final int SIGNATURE_MISSING = 10;

    /**
     * The JWT had no Issuer "iss" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int ISSUER_MISSING = 11;

    /**
     * The Issuer "iss" claim was invalid based on the issuer that the <code>JwtConsumer</code>
     * was set up to expect.
     */
    public static final int ISSUER_INVALID = 12;

    /**
     * The JWT had no JWT ID "jti" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int JWT_ID_MISSING = 13;

    /**
     * The JWT had no Subject "sub" claim but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int SUBJECT_MISSING = 14;

    /**
     * The Subject "sub" claim was invalid based on the subject that the <code>JwtConsumer</code>
     * was set up to expect.
     */
    public static final int SUBJECT_INVALID = 15;

    /**
     * The JWS/JWE payload could not be parsed as JSON.
     */
    public static final int JSON_INVALID = 16;

    /**
     * Miscellaneous.
     */
    public static final int MISCELLANEOUS = 17;

    /**
     * A JWT claim was of the wrong type or otherwise malformed.
     */
    public static final int MALFORMED_CLAIM = 18;

    /**
     * No JWE encryption was present but the <code>JwtConsumer</code> was
     * set up to require it.
     */
    public static final int ENCRYPTION_MISSING = 19;

    /**
     * The <code>JwtConsumer</code> was set up to require a JOSE algorithm that provides integrity protection
     * (signature/MAC JWS or symmetric JWE) but no such protection was present on the JWT.
     */
    public static final int INTEGRITY_MISSING = 20;

    /**
     * No "typ" header parameter was present in the innermost JWS/JWE but the <code>JwtConsumer</code> was
     * set up to require explicit typing.
     */
    public static final int TYPE_MISSING = 21;

    /**
     * The type "typ" header value was invalid based on the type that the <code>JwtConsumer</code>
     * was set up to expect.
     */
    public static final int TYPE_INVALID = 22;

    /**
     * The value of the Issued At "iat" claim is too far in the future.
     */
    public static final int ISSUED_AT_INVALID_FUTURE = 23;


    /**
     * The value of the Issued At "iat" claim is too far in the past.
     */
    public static final int ISSUED_AT_INVALID_PAST = 24;

}
