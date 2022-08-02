package org.jose4j.jwe;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;


/**
 *
 */
public class InvalidCurveTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void testRejectInvalidCurve() throws JoseException
    {
        // test vectors and most of the test provided by Antonio Sanso

        String alg = "ECDH-ES+A128KW";
        String enc = "A128CBC-HS256";

        String receiverJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n" +
                " \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n" +
                " \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n" +
                "}";
        PublicJsonWebKey receiverJwk = PublicJsonWebKey.Factory.newPublicJwk(receiverJwkJson);

        ECPrivateKey privateKeyImpl = (ECPrivateKey) receiverJwk.getPrivateKey();
        BigInteger receiverPrivateKey = privateKeyImpl.getS();

        //========================= attacking point #1 with order 113 ======================
        BigInteger attackerOrderGroup1 = new BigInteger("113");
        BigInteger receiverPrivateKeyModAttackerOrderGroup1 = receiverPrivateKey.mod(attackerOrderGroup1);

        log.debug("The receiver private key is equal to {} mod {}", receiverPrivateKeyModAttackerOrderGroup1, attackerOrderGroup1);

        //The malicious JWE contains a public key with order 113
        String maliciousJWE1 = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1Rsa" +
                "TY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta" +
                "2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9f" +
                "wUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w";

        log.debug("JWE w/ {} & {}: {}", alg, enc, maliciousJWE1);

        JsonWebEncryption receiverJwe1 = new JsonWebEncryption();
        receiverJwe1.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW));
        receiverJwe1.setCompactSerialization(maliciousJWE1);
        receiverJwe1.setKey(receiverJwk.getPrivateKey());
        //this proof that receiverPrivateKey is equals 26 % 113
        try
        {
            String plaintextString = receiverJwe1.getPlaintextString();
            Assert.fail("Decryption should have failed due to invalid curve. But got plaintext '" + plaintextString + "'");
        }
        catch (Exception e)
        {
            log.debug("Decryption failed as expected: " + e.toString());
        }

        //========================= attacking point #2 with order 2447 ======================
        BigInteger attackerOrderGroup2 = new BigInteger("2447");
        BigInteger receiverPrivateKeyModAttackerOrderGroup2 = receiverPrivateKey.mod(attackerOrderGroup2);

        log.debug("The receiver private key is equal to {} mod {}", receiverPrivateKeyModAttackerOrderGroup2, attackerOrderGroup2);

        //The malicious JWE contains a public key with order 2447
        String maliciousJWE2 = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1" +
                "E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZ" +
                "qVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1Uslv" +
                "tkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A";
        log.debug("JWE w/ {} & {}: {}", alg, enc, maliciousJWE1);

        JsonWebEncryption receiverJwe2 = new JsonWebEncryption();
        receiverJwe2.setAlgorithmConstraints(new AlgorithmConstraints(PERMIT, KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW));
        receiverJwe2.setCompactSerialization(maliciousJWE2);
        receiverJwe2.setKey(receiverJwk.getPrivateKey());
        //this proof that receiverPrivateKey is equals 2446 % 2447

        try
        {
            String plaintextString = receiverJwe2.getPlaintextString();
            Assert.fail("Decryption should have failed due to invalid curve. But got plaintext '" + plaintextString + "'");
        }
        catch (Exception e)
        {
            //
            log.debug("Decryption failed as expected: " + e.toString());
        }

        //THIS CAN BE DOIN MANY TIME
        //....
        //AND THAN CHINESE REMAINDER THEOREM FTW

    }
}
