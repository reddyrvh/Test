package org.jose4j.jws;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

import static org.hamcrest.CoreMatchers.*;
import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.*;
import static org.junit.Assert.*;

/**
 *
 */
public class JwsUnencodedPayloadOptionTest
{
    @Test
    public void rfc7797Examples() throws Exception
    {
        // the key and payload are from https://tools.ietf.org/html/rfc7797#section-4
        String payload = "$.02";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(
                "   {\n" +
                "      \"kty\":\"oct\",\n" +
                "      \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\n" +
                "           aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"\n" +
                "   }\n");

        // Test the "control" JWS from https://tools.ietf.org/html/rfc7797#section-4.1
        String controlCompactSerialization = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
        JsonWebSignature controlJws = new JsonWebSignature();
        controlJws.setCompactSerialization(controlCompactSerialization);
        controlJws.setKey(jwk.getKey());
        controlJws.setPayloadCharEncoding(StringUtil.US_ASCII);
        assertTrue(controlJws.verifySignature());
        assertThat(payload, equalTo(controlJws.getPayload()));


        // Test verifying the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
        String detachedUnencoded = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, AlgorithmIdentifiers.HMAC_SHA256));
        jws.setPayloadCharEncoding(StringUtil.US_ASCII);
        jws.setCompactSerialization(detachedUnencoded);
        jws.setKey(jwk.getKey());
        jws.setPayload(payload);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));

        // reconstruct the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
        // the header just works out being the same based on (a little luck and) setting headers order and how the JSON is produced
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
        jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        jws.setPayloadCharEncoding(StringUtil.US_ASCII);
        jws.setKey(jwk.getKey());
        jws.setPayload(payload);
        String detachedContentCompactSerialization = jws.getDetachedContentCompactSerialization();
        assertThat(detachedUnencoded, equalTo(detachedContentCompactSerialization));
        assertThat(payload, equalTo(jws.getUnverifiedPayload()));
    }

    @Test
    public void rfc7797ExampleWithDirectJwsSetHeader() throws Exception
    {
        // the key and payload are from https://tools.ietf.org/html/rfc7797#section-4
        String payload = "$.02";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(
                "   {\n" +
                        "      \"kty\":\"oct\",\n" +
                        "      \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\n" +
                        "           aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"\n" +
                        "   }\n");


        // Test verifying the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
        String detachedUnencoded = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";


        // reconstruct the example with unencoded and detached payload from https://tools.ietf.org/html/rfc7797#section-4.2
        // the header just works out being the same based on (a little luck and) setting headers order and how the JSON is produced
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setHeader(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
        jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        jws.setPayloadCharEncoding(StringUtil.US_ASCII);
        jws.setKey(jwk.getKey());
        jws.setPayload(payload);
        String detachedContentCompactSerialization = jws.getDetachedContentCompactSerialization();
        assertThat(detachedUnencoded, equalTo(detachedContentCompactSerialization));
        assertThat(payload, equalTo(jws.getUnverifiedPayload()));

        jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, AlgorithmIdentifiers.HMAC_SHA256));
        jws.setPayloadCharEncoding(StringUtil.US_ASCII);
        jws.setCompactSerialization(detachedUnencoded);
        jws.setKey(jwk.getKey());
        jws.setPayload(payload);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));
        Object objectHeader = jws.getObjectHeader(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        assertFalse((boolean)objectHeader);

    }


    @Test
    public void testExamplesFromDraftEvenWithoutDirectSupportForTheHeader() throws Exception
    {
        // a test of sorts to verify the examples from
        // http://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-09#section-4
        // at Mike's request

        String jwkJson =
                "{" +
                "  \"kty\":\"oct\"," +
                "  \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
                "      aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"" +
                "}";
        final JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwkJson);
        final Key key = jsonWebKey.getKey();

        String payload = "$.02";

        final String encodedPayload = Base64Url.encode(payload, StringUtil.US_ASCII);
        assertThat(encodedPayload, equalTo("JC4wMg"));

        String jwscsWithB64 = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscsWithB64);
        jws.setKey(key);
        assertThat(jws.getPayload(), equalTo(payload));
        assertTrue(jws.verifySignature());

        jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(key);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        assertThat(jws.getCompactSerialization(), equalTo(jwscsWithB64));

        String jwscsWithoutB64andDetachedPaylod = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.." +
                "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscsWithoutB64andDetachedPaylod);
        assertThat(jws.getHeaders().getFullHeaderAsJsonString(), equalTo("{\"alg\":\"HS256\",\"b64\":false,\"crit\":[\"b64\"]}"));

        HmacUsingShaAlgorithm.HmacSha256 hmacSha256 = new HmacUsingShaAlgorithm.HmacSha256();

        final String signingInputString = jws.getHeaders().getEncodedHeader() + "." + payload;

        final byte[] signatureBytes = Base64Url.decode(jws.getEncodedSignature());
        final byte[] securedInputBytes = StringUtil.getBytesAscii(signingInputString);
        final ProviderContext providerContext = new ProviderContext();
        boolean okay = hmacSha256.verifySignature(signatureBytes, key, securedInputBytes, providerContext);
        assertTrue(okay);

        CryptoPrimitive cryptoPrimitive = hmacSha256.prepareForSign(key, providerContext);
        final byte[] signed = hmacSha256.sign(cryptoPrimitive, securedInputBytes);
        assertThat(Base64Url.encode(signed), equalTo(jws.getEncodedSignature()));
    }

    @Test
    public void compactSerializationUnencodedPayload() throws JoseException
    {
        // https://bitbucket.org/b_c/jose4j/issues/156 shows the b64:false didn't work (0.6.5 and prior)
        // with compact serialization.

        String payload = "{\"key\": \"value\"}";

        JsonWebSignature signerJws = new JsonWebSignature();
        signerJws.setPayload(payload);
        signerJws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
        signerJws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        signerJws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        signerJws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        String compactSerialization = signerJws.getCompactSerialization();
        assertThat(compactSerialization, containsString(payload));

        JsonWebSignature verifierJws = new JsonWebSignature();
        verifierJws.setCompactSerialization(compactSerialization);
        verifierJws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertTrue(verifierJws.verifySignature());
        assertThat(payload, is(equalTo(verifierJws.getPayload())));


        payload = "I want a hamburger. No, a cheeseburger. I want a hotdog. I want a milkshake.";

        signerJws = new JsonWebSignature();
        signerJws.setPayload(payload);
        signerJws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
        signerJws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
        signerJws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        signerJws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        try
        {
            compactSerialization = signerJws.getCompactSerialization();
            fail("JWS Compact Serialization with unencoded non-detached payloads cannot have period ('.') characters but " + compactSerialization);
        }
        catch (JoseException e)
        {
            Logger log = LoggerFactory.getLogger(this.getClass());
            log.debug("Expected exception because JWS Compact Serialization with unencoded non-detached payloads cannot have period ('.') characters : {}", e.toString());
        }
    }
}
