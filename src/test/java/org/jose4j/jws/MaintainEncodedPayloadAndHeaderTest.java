package org.jose4j.jws;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwt.consumer.SimpleJwtConsumerTestHelp;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class MaintainEncodedPayloadAndHeaderTest
{
    @Test
    public void testOddEncodedPayload() throws Exception
    {
        // There's an extra 'X' at the end of the encoded payload but it still decodes to the same value as when the 'X' isn't there
        // but the signature is over the X and we want to check what was signed rather than what we think should be signed by re-encoding the payload
        final String funkyToken = "eyJhbGciOiJSUzI1NiJ9." +
                "IVRoaXMgaXMgbm8gbG9uZ2VyIGEgdmFjYXRpb24uX." +
                "f6qDgGZ8tCVZ_DhlFwWAZvV-Vv5yQOFSAXVv98vOpgkI6YQd6hjCWaeyaWbMWhV__uiWiEY0SutaQw1y71bXvRPfy12YKpyIlRwvos9L5myA--GGc6o88hDjxxc2PLhhhNazR" +
                "1aSVXIb6wF4PJENb10XDMIuMj9wtzDVnLajS5O3Ptygwx39bRa9XoXrAxbSyEBJSV9nVCQS-wPRaEudDcLRQhKVhMHYJ-3UZn0VVpCz_8KWvw4JOB9jWntS85CPF4RcUaepQJ" +
                "2pz-8gfCrv2qKHKU36FbmqOwKoQZL1dLXH1wp33k7ESt5zivLVPli3tPDVfBa5BmWAMO1mydqGgw";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(funkyToken);
        jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertThat(jws.getPayload(), equalTo("!This is no longer a vacation."));
    }

    @Test
    public void jwtSec31ExampleJWTWithExtraStuffPrependedToHeader() throws Exception
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
        // with "!!!!" prepended to the front of the JWT should have an invalid signature
        String jwt = "!!!!eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        checkWithExtraStuffOnHeader(jwt);
    }

    @Test
    public void jwtSec31ExampleJWTWithExtraStuffOnToHeader() throws Exception
    {
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9===." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        checkWithExtraStuffOnHeader(jwt);
    }

    @Test
    public void jwtSec31ExampleJWTWithExtraStuffOnToHeader2() throws Exception
    {
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9X." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        checkWithExtraStuffOnHeader(jwt);
    }


    private void checkWithExtraStuffOnHeader(String jwt) throws JoseException
    {
        String jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwk);

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(jsonWebKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
    }
}
