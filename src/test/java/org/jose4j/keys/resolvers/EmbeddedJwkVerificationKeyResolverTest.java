package org.jose4j.keys.resolvers;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwt.consumer.SimpleJwtConsumerTestHelp;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.HashUtil;
import org.junit.Test;

import java.security.Key;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class EmbeddedJwkVerificationKeyResolverTest
{
    @Test
    public void testDpopExamples() throws InvalidJwtException, MalformedClaimException
    {
        // from pre -03 https://tools.ietf.org/html/draft-fett-oauth-dpop there's a JWT with a jwk header
        String jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoU" +
                "klDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R" +
                "2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM3lFU2MwNGFjYzc3bFRjMjZ4IiwiaHRtIjoiUE9TVCIsImh0dSI6" +
                "Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.1bviyKqc_-6h3bGPT7jL27jO3KG" +
                "55wEONmboEoZou0fbIIifsFmp_UwPE3kj0G9sEA5AN9jjzHeRNF6rn-scrw";

        EmbeddedJwkVerificationKeyResolver embeddedJwkVerificationKeyResolver = new EmbeddedJwkVerificationKeyResolver();
        JwtConsumerBuilder b = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1562262626))
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(10, 60)
                .setVerificationKeyResolver(embeddedJwkVerificationKeyResolver)
                .setExpectedType(true,"application/dpop+jwt");
        JwtConsumer consumer = b.build();
        JwtClaims claims = consumer.processToClaims(jwt);

        assertThat("POST", is(equalTo(claims.getStringClaimValue("htm"))));
        assertThat("https://server.example.com/token", is(equalTo(claims.getStringClaimValue("htu"))));

        PublicJsonWebKey jwk = embeddedJwkVerificationKeyResolver.getJwk();
        String thumbprint = jwk.calculateBase64urlEncodedThumbprint(HashUtil.SHA_256);

        // compare (by thumbprint) the key in the header to the document
        assertThat("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", is(equalTo(thumbprint)));

        // no jwk header in this one so the jwt processing should fail
        jwt = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJqdGkiOiItQndDM3lFU2MwNGFjYzc3bFRjMjZ4IiwiaHRtIjoiUE9TV" +
                "CIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.DlWrKDQE15d6lN14J" +
                "525P877gT_pmYYKFwpFmUvs3uQ96wTHV-4ZdnozfXVmlHmpgF5DA_3Ld8x5iyS7MrOjhw";
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void testRoundTripping() throws Exception
    {
        String jwkJson = "{  \n" +
                "   \"kty\":\"RSA\",\n" +
                "   \"n\":\"pVxL168uDaEFo9vMjLBcwtrOSi1kzceo4IGclkRtaxjOhxfYIBYw1UgdxkEn-3xUXadBFgQI9kas4EJH3vpZUPcVyHRKmNy9VVwTyq-ka9qfSl3bLkgkzLrWve8vxRoTAhDrX3EHxwZ00yQ0F7Rk1JOx9Dly-Cv4_NCdKFC5ULukDxWEKVFCLw1FjabNSnpQuGxGmzN7vgLc9V68pB809kctIsL5M4YLdoWOqo4YVMmLgg8v9uLz05vKnaoJ7g3Tf9PqCIwNAhMswvIiHmt_ipfu2wNrhAmEtsf-kBhtHnmp7jWZxaUZRoNVjwCEeERdAObVVYvZ2Y9sRVUR46LYsw\",\n" +
                "   \"e\":\"AQAB\",\n" +
                "   \"d\":\"hHA0ii1S3DWP99nNrQx_bsyiFgTfTHTRy-XjDPMHE5SNrOMrBR_gwqF8v1Fl_WRpiYywczqOFvkp8n8DYxHtQQx0FNUW_fElbt1NOLOOI5e4pm4fYqUDXDl0TjDoeJtWh_wXF5zGlt-T55uCYU3ox9z21NzCOQO26n0Gschdc8tU6wSG0YhnXGsIESkcJUG28YOjf-jnsbEus-V9dq3Ft5OuJI5TTQMm2gxKJGFi9V7pLXYF5iKc0tvU0HtIjIT7sYbgUw4yQHk50OgcmP-iWPYKj1sRIUuDYQFR_1KeHgh9m6dRd3EJRN0MQnWAMSEtykKEomlkczP-rabbDYzPCQ\",\n" +
                "   \"p\":\"-5IQbu2UmL4papzjwHqzPMbxJ4uu4O07FrYbod0hRDsPEsGArOBAYUd9vPVxJfXMb6xSYnSiuCsmvGxYDlqTQx-bUjxgh_rP6zZK2V_PKSrxipPZRN_yx8gXGgNK8etlpLS20bCoMRWwWdhfmfrOMDz0xU2DtiQ28RySlgcTHa8\",\n" +
                "   \"q\":\"qEWljcS7XXRy0Y-HaPW7mJF13lZbhqK3OB6w8ArXs3oJxBnTNehwgIMHs4EnTybFDCDjth8tdznbvypopGCbWjjAe4oPzQrB4bdoTqA-eUglEKRAwSO46qsZYxTOPC2KI3Pt8oFRb3SwY3p-ZFMcaQBw5SG6zV07U2ClI5s_Gj0\",\n" +
                "   \"dp\":\"9PnQzOTIPlF3rV0oH8icgAPO1E6etmPtlXkywVW_zlygmgga0L3zk4d1tytfyrJoKRsqgrvHtQY4S2ZJ_XhQTR4bN2KaMfCYxhjxnGpDJniuC99bxUk7dzau4GLyeVBcg56DJQEdV-ch-uvMdPqaDLlfNj78ksMDSZokWLp87_s\",\n" +
                "   \"dq\":\"j1_IT6LwghBWRHgmyCeYT8agx3CNS4oY0phT6jNS1nmFGLFoZOZH9TevuCKze51tB4h-fQ7TjmKd-aQIxQYLWDRCzQA1tl8UE15SYavnjy8JZcSN6AKn7Esctm9jyaKDsPF2LMpCuNST9i7IwnKOImldx92VbKWjhscx7cS5X4E\",\n" +
                "   \"qi\":\"T8Of3qCf6snckcSWUOGim3LnfAnzT87cR_qZZOHzF8wD_rvfBi0DGWuOaBavTFgiIow0wBZBd71MqYdIFfHm4muI-z08d0ZeZrKPljNGVl46_mICTWA-W6yGk6ez5lcam84xJhSXH5xDEwMtbWMiCs5vqq5JkU9vq0DCbyDT5yk\"\n" +
                "}";
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJson);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setHeader(HeaderParameterNames.TYPE, "dpop+jwt");
        jws.setJwkHeader(jwk);
        jws.setKey(jwk.getPrivateKey());
        JwtClaims claims = new JwtClaims();
        claims.setJwtId("abc123");
        claims.setStringClaim("htm", "GET");
        claims.setStringClaim("htu", "https://api.example.com/whatever");
        claims.setIssuedAtToNow();
        jws.setPayload(claims.toJson());

        String jwt = jws.getCompactSerialization();

        EmbeddedJwkVerificationKeyResolver embeddedJwkResolver = new EmbeddedJwkVerificationKeyResolver();
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(embeddedJwkResolver)
                .setExpectedType(true, "dpop+jwt")
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(5, 30)
                .build();
        JwtContext context = jwtConsumer.process(jwt);

        assertThat("GET", is(equalTo(context.getJwtClaims().getStringClaimValue("htm"))));
        assertThat("https://api.example.com/whatever", is(equalTo(context.getJwtClaims().getStringClaimValue("htu"))));

        PublicJsonWebKey inlineJwk = embeddedJwkResolver.getJwk();
        byte[] thumbprint = inlineJwk.calculateThumbprint(HashUtil.SHA_256);
        assertThat(jwk.calculateThumbprint(HashUtil.SHA_256), is(equalTo(thumbprint)));

        Key key = context.getJoseObjects().get(0).getKey();
        assertThat(key, is(equalTo(jwk.getKey())));


    }

    @Test
    public void testMakeSureJwkHeaderWithPrivateKeyIsRejected() throws Exception
    {
        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Ijc2blk4UGtTVkE4MG" +
                "lPUHEzVUVHbm9jdU9HaFFqR09rY1BwYnlXcHNXbWciLCJ5IjoiMDBMWkIySWNPeEVya05ad2NRWF9kbXVkay1hdE9STUtqR" +
                "EJUc1VlTXZvVSIsImNydiI6IlAtMjU2IiwiZCI6IklJYlhwVWJJSGVtT0FyZWVRX0xNMmFrcTd5NjZEY1lsdXZneWRPcml0" +
                "SlUifX0.eyJqdGkiOiJiYzc4OSIsImh0bSI6IkdFVCIsImh0dSI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tIiwiaWF0Ijo" +
                "xNjQ3OTU5MTMyfQ.-GKT4h58oZzS4LGk8b44Dh4GoJ9Y2extHUOr_LzbFIibO_XXfanPZ8ePZkXd8s7cuQyFKagePUVCdu1" +
                "T2UKbTQ";

        EmbeddedJwkVerificationKeyResolver embeddedJwkResolver = new EmbeddedJwkVerificationKeyResolver();
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(embeddedJwkResolver)
                .setEvaluationTime(NumericDate.fromSeconds(1647959133))
                .setExpectedType(true, "dpop+jwt")
                .setRequireIssuedAt()
                .setIssuedAtRestrictions(5, 30)
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtConsumer);
    }
}