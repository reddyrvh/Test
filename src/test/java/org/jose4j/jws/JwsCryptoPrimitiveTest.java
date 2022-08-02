package org.jose4j.jws;

import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.HmacKey;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwsCryptoPrimitiveTest
{
    private static final Logger log = LoggerFactory.getLogger(JwsCryptoPrimitiveTest.class);

    @Test
    public void exerciseTheApi() throws Exception
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("It’s a one-year membership in the jelly-of-the-month club.");
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        CryptoPrimitive cryptoPrimitive = jws.prepareSigningPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNotNull(cryptoPrimitive.getSignature());
        log.debug("cryptoPrimitive.getSignature(): " + cryptoPrimitive.getSignature());
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        Assert.assertTrue(jws.verifySignature());
        Assert.assertTrue(jws.getPayload().contains("jelly-of-the-month"));


        jws = new JsonWebSignature();
        jws.setPayload("Clark, that’s the gift that keeps on giving the whole year.");
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        cryptoPrimitive = jws.prepareSigningPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNotNull(cryptoPrimitive.getSignature());
        log.debug("cryptoPrimitive.getSignature(): " + cryptoPrimitive.getSignature());
        compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        Assert.assertTrue(jws.verifySignature());
        Assert.assertTrue(jws.getPayload().contains("Clark,"));


        jws = new JsonWebSignature();
        HmacKey hmacKey = new HmacKey(new byte[]{1, 0, 8, -17, 1, 33, 4, 14, 44, 120, 88, 99, 98, 91, 94, 78, 0, 1,
                -17, 1, 34, 0, 120, 88, 99, 98, 91, 2, 0, 8, -111, 1, 3});
        jws.setKey(hmacKey);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        cryptoPrimitive = jws.prepareSigningPrimitive();
        Assert.assertNull(cryptoPrimitive.getKey());
        Assert.assertNull(cryptoPrimitive.getKeyAgreement());
        Assert.assertNotNull(cryptoPrimitive.getMac());
        Assert.assertNull(cryptoPrimitive.getCipher());
        Assert.assertNull(cryptoPrimitive.getSignature());
        log.debug("cryptoPrimitive.getMac(): " + cryptoPrimitive.getMac());
        jws.setPayload("I had a lot of help from Jack Daniels.");
        compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(hmacKey);
        Assert.assertTrue(jws.verifySignature());
        Assert.assertTrue(jws.getPayload().contains("Daniels"));
    }
}
