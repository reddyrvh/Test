package org.jose4j.jws;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;

/**
 *
 */
public class JwsPayloadVariationsTest
{
    @Test
    public void rawBytesAsPayload() throws Exception
    {
        JsonWebSignature jws = new JsonWebSignature();
        byte[] bytesIn = {-98,96,-6,55,-118,-17,-128,13,126,14,90,-21,-91,-7,-50,-57,37,79,10,45,52,77,87,
                -24,-18,-94,-45,100,-18,110,-20,-23,-123,120,99,-43,115,126,103,0,-18,-43,22,-76,-84,127,
                -110,7,78,-109,44,81,119,-73,-115,-10,18,27,-113,-104,14,-50,-105,-41,-49,25,26,116,-37,
                -42,75,-109,-30,-62,117,-44,100,-114,43,-125,123,39,-79,-55,-111,-36,86,42,-55,123,-16,
                -74,119,59,-68,-4,-119,-118,-101,-76};
        jws.setPayloadBytes(bytesIn);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        byte[] bytesOut = jws.getPayloadBytes();

        Assert.assertArrayEquals(bytesIn, bytesOut);

        Assert.assertTrue(jws.verifySignature());
    }

    @Test
    public void getPayloadBytesThrowsOnBadSignature() throws Exception
    {
        JsonWebSignature jws = new JsonWebSignature();
        byte[] bytesIn = {12,6,-16,44,0,-17,-128,113,126,14,43,-121,123,35,-40,-7,37,79,10,45,77,77};
        jws.setPayloadBytes(bytesIn);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        String compactSerialization = jws.getCompactSerialization();

        PublicJsonWebKey wrongKey = PublicJsonWebKey.Factory.newPublicJwk("{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"n\": \"xLyNk8AVckm8PPwxHfenLe1MvDHJL4UsOqGgbyAsEBqrATEg0aapHuwJPFoiRCHQW0cgA8B9V8_MElHtMmU89" +
                "VLRIeln7WCouCasO1rl2DHvBZAGhDLX5yDNTPs8-jrrZKqE_KgJQZV0KphDcwIVwgljtswPLiP2FgqjbnUivVM7wHbMR6kdl" +
                "_FP-VwmWJFUYCtHVOJ9DalhATFndThCZ-LAgjt6tAuWiW6kEUtXuX3RfMNHh1AOufLeHp7ywmh6DhSfOjcBNVHz9Wi6vlAPh" +
                "Ypk2G9xXtE9-78z76lR2T0YtULN7xDRwHSq1ub_T3Y4whxp4jYbVWRuOkqifz3TuQ\"\n" +
                "}");

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(wrongKey.getKey());
        byte[] bytesOut;
        try
        {
            bytesOut = jws.getPayloadBytes();
            Assert.fail("getPayloadBytes() should have thrown an exception due to invalid signature but " + Arrays.toString(bytesOut));
        }
        catch (JoseException e)
        {
            LoggerFactory.getLogger(this.getClass()).debug("Expected: " + e);
        }

        bytesOut = jws.getUnverifiedPayloadBytes();
        Assert.assertArrayEquals(bytesIn, bytesOut);
    }

    @Test
    public void payloadCharEncodingASCII() throws Exception
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayloadCharEncoding("US-ASCII");
        jws.setPayload("pronounced as'-key");

        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();

        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jws.setPayloadCharEncoding("US-ASCII");
        Assert.assertTrue(jws.verifySignature());

        Assert.assertThat("pronounced as'-key", equalTo(jws.getPayload()));
    }

    @Test
    public void payloadCharEncodingISO8859_15() throws Exception
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayloadCharEncoding("ISO8859_15");
        jws.setPayload("€Ÿ");

        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();

        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jws.setPayloadCharEncoding("US-ASCII");
        Assert.assertThat("€Ÿ", not(equalTo(jws.getPayload())));
        jws.setPayloadCharEncoding("ISO8859_15");
        Assert.assertTrue(jws.verifySignature());
        Assert.assertThat("€Ÿ", equalTo(jws.getPayload()));
        Assert.assertThat("ISO8859_15", equalTo(jws.getPayloadCharEncoding()));
    }
}
