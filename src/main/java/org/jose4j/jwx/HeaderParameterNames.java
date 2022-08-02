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

package org.jose4j.jwx;

/**
 */
public class HeaderParameterNames
{
    public static final String ALGORITHM = "alg";

    public static final String ENCRYPTION_METHOD = "enc";

    public static final String KEY_ID = "kid";

    public static final String TYPE = "typ";

    public static final String CONTENT_TYPE = "cty";

    public static final String JWK_SET_URL = "jku";

    public static final String JWK = "jwk";

    public static final String X509_CERTIFICATE_CHAIN = "x5c";

    public static final String X509_CERTIFICATE_THUMBPRINT = "x5t";

    public static final String X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#S256";

    public static final String X509_URL = "x5u";

    public static final String EPHEMERAL_PUBLIC_KEY = "epk";

    public static final String AGREEMENT_PARTY_U_INFO = "apu";
    public static final String AGREEMENT_PARTY_V_INFO = "apv";

    public static final String ZIP = "zip";

    public static final String PBES2_SALT_INPUT = "p2s";
    public static final String PBES2_ITERATION_COUNT = "p2c";

    public static final String INITIALIZATION_VECTOR = "iv";
    public static final String AUTHENTICATION_TAG = "tag";

    public static final String CRITICAL = "crit";


    /**
     * As defined in RFC 7797, the "b64" (base64url-encode payload) Header Parameter determines
     * whether the payload is represented in the JWS and the JWS Signing
     * Input as ASCII(BASE64URL(JWS Payload)) or as the JWS Payload value
     * itself with no encoding performed.
     *
     * https://tools.ietf.org/html/rfc7797
     */
    public static final String BASE64URL_ENCODE_PAYLOAD = "b64";
}
