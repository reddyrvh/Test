package org.jose4j.jwk;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class VerificationJwkSelectorTest
{
    @Test
    public void uniqueKidTests() throws JoseException
    {
        // JSON content from a PingFederate JWKS endpoint (a snapshot build circa Jan '15)
        String json = "{" +
                "  \"keys\": [" +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2ym\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9ou3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\"," +
                "      \"y\": \"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrvP2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yl\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\"," +
                "      \"y\": \"Bt0HwjlM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yk\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\"," +
                "      \"y\": \"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"zq2yj\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yi\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"Aeu8Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNae81RujWu3aSEWoX1aAVRh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\"," +
                "      \"y\": \"AOlx2rRLBLI3nh3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92ADYJBItvRdKcBk-BYb4Cewma7KtNuIK8zZ2HEen6d\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yh\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"gcqegh2wqsLgmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwTlhNMc4V8FO01Jt\"," +
                "      \"y\": \"-bO4V5xtasOgWsrCGs_bydqT0o3O29cA-5Sl7aqSfB7Z5-N3Dki5Ed2RZEU0Q7g0\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yg\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"6elUcv15VpXlU995KVHZ3Jx6V8Cq7rCoodyIaXbQxS8\"," +
                "      \"y\": \"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu8\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"zq2yf\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"wbcVJs-T_yP6TEWmdAqTo3qFsdtpffUEqVbxtaWr-PiXs4DTWtig6kYO1Hwim0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a1V3fov09BmfODE7MRVEqmZXHRxGUxXLGZn294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVHUP_xo5vRxQ0tTO0z1YHfjNNpycLlCNOoxbuN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2ye\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGwHIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVccvz0SD7es-\"," +
                "      \"y\": \"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8UdiLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yd\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"cLP7G_dHWU7CGlB3h2Rt-yr4cuT2-ybk6Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\"," +
                "      \"y\": \"-OzAuuaPViw3my3UAE3WiXOYlaa5MYz7dbMBSZjZhretKm118itVnCI_WRAkWMa7\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"zq2yc\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"IUk0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnqVZ5DTmI\"," +
                "      \"y\": \"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"zq2yb\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"lMRL3ng10Ahvh2ILcpEiKNi31ykHP8Iq7AENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGlKiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lKD6q7_UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtMmZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysarzW_mUX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\"," +
                "      \"e\": \"AQAB\"" +
                "    }" +
                "  ]" +
                "}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("zq2yb");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("zq2yb", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setKeyIdHeaderValue("zq2yf");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("zq2yf", equalTo(selected.get(0).getKeyId()));

        // a kid that's not in there
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("nope");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(0, equalTo(selected.size()));

        // a kid that is in there but for the wrong key type
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("zq2yg");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(0, equalTo(selected.size()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("zq2yi");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("zq2yi", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
        jws.setKeyIdHeaderValue("zq2yh");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("zq2yh", equalTo(selected.get(0).getKeyId()));

        // real kid, wrong key type
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("zq2yj");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(0, equalTo(selected.size()));

        // what would likely be the next kid
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("zq2y0");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(0, equalTo(selected.size()));
    }

    @Test
    public void uniqueKidTestsGooglesJwksEndpoint() throws JoseException
    {
        // JSON content from https://www.googleapis.com/oauth2/v2/certs on Jan 7, 2015
        String json =
                "{\n" +
                " \"keys\": [\n" +
                "  {\n" +
                "   \"kty\": \"RSA\",\n" +
                "   \"alg\": \"RS256\",\n" +
                "   \"use\": \"sig\",\n" +
                "   \"kid\": \"da522f3b66777ff6af63460d2b549ad43b6660d6\",\n" +
                "   \"n\": \"69Eh051UHkBJx55OkavsrpeeulxaHzxC9pMjVNQnjhY5pwJ0YjB_FgJwOdFHEdPOc8uzi_Pnfr0ov0mE4cRTjnEsSF9_sB0sJaLE-W5e54-UxwgEPNWd4qT-sYdBl5LOwRoCth9gJ_6YA0zCr0V3AmAwoPnYRC9xo0R5aZY4Xvk=\",\n" +
                "   \"e\": \"AQAB\"\n" +
                "  },\n" +
                "  {\n" +
                "   \"kty\": \"RSA\",\n" +
                "   \"alg\": \"RS256\",\n" +
                "   \"use\": \"sig\",\n" +
                "   \"kid\": \"3b2b4413738f55cb2405ee30334082be07e0fcc0\",\n" +
                "   \"n\": \"8A6XgAQoenKyOJCz6AA-YZ3oN1GTEr3TVvJLV5ZoFdmPNvUohB2RXEJ4jRY16_z2SUK40ZPl_XPCAjl7vzf0BznUJYV33JwZFmCYoSWofllQUQu2iaJjyuQG7_PSYhBO5XxfTcIZGL6n4_87vp9jIFdm5J9bZgvwUgI5q7iooJs=\",\n" +
                "   \"e\": \"AQAB\"\n" +
                "  }\n" +
                " ]\n" +
                "}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("da522f3b66777ff6af63460d2b549ad43b6660d6");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("da522f3b66777ff6af63460d2b549ad43b6660d6", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("3b2b4413738f55cb2405ee30334082be07e0fcc0");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("3b2b4413738f55cb2405ee30334082be07e0fcc0", equalTo(selected.get(0).getKeyId()));

        // a kid that's not in there
        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("nope");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(0, equalTo(selected.size()));
    }

    @Test
    public void uniqueKidTestsSalesforceJwksEndpoint() throws JoseException
    {
        // JSON content from https://login.salesforce.com/id/keys on Jan 7, 2015
        String json = "{\"keys\":[" +
                "{\"kty\":\"RSA\",\"n\":\"wIQtK09qsu1qCCQu1mHh6d_EyyOlbqMCV8WMacOyhZng1sbaFJY-0PIH46Kw1uhjbHg94_r2UELYd30vF8xwViGhCmpPuSGhkxNoT5CMoJPS6JW-zBpR7suHqBUnaGdZ6G2uYZDpwWYs_4SJDuWzxVBrQqIM_ZVgUqutniQPmjMAX5MqznBTnG3zm728BmNzS7T2gtzxs3jAgDsSAu3Kxp3D6NDGERhaAJ8jOgwHvmQK5xFi9Adw7sv2nCH-wM-C5fLJYmpGOSrTP1HLOlq--TROAvWL9gcNEeq4arryIYux5syg66rHT8U2Uhb1PdXt7ReQY8wBnP2BBH1QH7rzOZ7UbqFLbQUQsZFAVMcfm7gJN8JWLlcSJZdC2zaY0wI5q8PWN-N_GgAK64FKZQ7pB0bRQ5AQx-D3U4sYE4EcgSvV8fW86PaF1VXaHMFcom48gZ1GzE_V25uPb-0yue0cv9lejrIKDvRiJ5UiyUPphro4Aw2ZcDi_8r8rqfglWhcnB4bGSri4kEBb_IdwvqKwRCqxlNdRnU1ooQeUBaVRwdbpj23Z1qtYjB55Wf2KOCJ6ewMyddq4bEAG6KIqPmssT7_exvygUyuW6qhnCV-gTZEwFI0A6djsHM5itfkzNY47BeuAtGXjuaRnVYIEvTrnSj3Lx7YfvCIiGqFrG6y31Ak\",\"e\":\"AQAB\"," +
                    "\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"188\"}," +
                "{\"kty\":\"RSA\",\"n\":\"hsqiqMXZmxJHzWfZwbSffKfc9YYMxj83-aWhA91jtI8k-GMsEB6mtoNWLP6vmz6x6BQ8Sn6kmn65n1IGCIlWxhPn9yqfXBDBaHFGYED9bBloSEMFnnS9-ACsWrHl5UtDQ3nh-VQTKg1LBmjJMmAOHdBLoUikfpx8fjA1LfDn_1iNWnguj2ehgjWCuTn64UdUd84YNcfO8Ha0TAhWHOhkiluMyzGS0dtN0h8Ybyi5oL6Bf1sfhtOncUh1JuWMcmvICbGEkA_0vBbMp9nCvXdMlpzMOCIoYYkQ-25SRZ0GpIr_oBIZByEm1XaJIqNXoC7qJ95iAyWkUiSegY_IcBV3nMXr-kDNn9Vm2cgLEJGymOiDQKH8g7VjraCIrqWPD3DWv3Z6RsExs6i0gG3JU9cVVFwz87d05_yk3L5ubWb96uxsP9rkwZ3h8eJTfFrgMhk1ZwR-63Dk3ZLYisiAU0zKgr4vQ9qsCNPqDg0rkeqOY5k7Gy201_wh6Sw5dCNTTGmZZ1rNE-gyDu4-a1H40n8f2JFiH-xIOD9-w8HGYOu_oGlobK2KvzFYHTk-w7vtfhZ0j96UkjaBhVjYSMi4hf43xNbB4xJoHhHLESABLp9IYDlnzBeBXKumXDO5aRk3sFAEAWxj57Ec_DyK6UwXSR9Xqji5a1lEArUdFPYzVZ_YCec\",\"e\":\"AQAB\"," +
                    "\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"194\"}," +
                "{\"kty\":\"RSA\",\"n\":\"o8Fz0jXjZ0Rz5Kt2TmzP0xVokf-Q4Az-MQg5i5MCxNNTQiZp7VkwAZeM0mJ-mKDbCzPm9ws43v8cxeiIkVZQqrAocnnb90MDCnU-7oD7MvOU4SbmhuLzVCyVZPIBRq5z0OgjcwLeD4trOoogkLOu0kyuyzNoFkr712m_GZ1xic-X0MlFKq3-2cI4U2nEuuh-Xcy7bUqCx0zTJFPOOKghGYEZZ6biZ04VC-ERcW6cC19pEWm6vCqZJEsKPCfazVAoHKZAukNd0XLPQd_W6xAaGnp8e7a5tFHn6dU6ikhI94ZieVp6WItWsQTDwJH-D7bVpVRG-lWL74lgcuQdFAtldm__k7FvlTXdqiLrd0rYuDnTFiwUSsUXWBJbmGVsEOylZVPQAL-K7G7p3BRY4X26vOgfludwCOj7L7WFbd0IXziTm74xe2KZGKsFpoCjJI0z_D5Oe5bofswr1Ceafhl97suG7OoInobt7QAQnnLcBVzUPz_TflOXDc5UiePptA0bxdd8MVENiDbTGGNz6DCzfL986QfcJLPB8aZa3lFN0kWPBkOclZagL4WpyIllB6euvZ2hfpt8IY2_bmUN06luo6N7Fy0hSSFMWvfzaD8_Ff3czb1Kv-b0xI6Ugk4d67RNNSbTcRM2Muvx-dJgOyXqrc_hE96OOqcMjrGZJoXnCAM\",\"e\":\"AQAB\"," +
                    "\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"190\"}," +
                "{\"kty\":\"RSA\",\"n\":\"nOcQOvHV8rc-hcfP_RmxMGjyVlruSLeFXTojYcbixaAH36scUejjaws31orUjmYqB5isE9ntdsL4DnsdP_MDJ2mtYD2FIh8tBkJjgXitjdcDclrwELAx846wBIlSES8wR6czpdJZfSwhL_92EGpDH6z7lKEClqhDlbtZ-yFKFj9BQRwaEXWV7uuq23gxXOqyEN0WXl3ZJPgsodCnlXRn9y_r5CNV9V4wvzXGlJhT3Nv_N_Z5XNZIjZnHdCuE_itT4a1xENEEds7Jjg5mRTlVFzYv5iQtBo7jdY5ogMTgKPmRh6hYuqLeki3AOAUff1AGaN9TZH60UxwTw03-DQJL5C2SuC_vM5KIWxZxQniubfegUCBXpJSAJbLt8zSFztTcrLS4-wgUHo1A8TDNaO28_KsBUTWsrieOr3NfCn4bPNb7t8G90U60lW0GIhEda3fNYnV0WWpZVO1jCRNy_JYUs3ECo0E1ZQJZD72Dm6UjiuH7eR3ZgNKR9tlLNdyZSpZUZPErLrXJ90d5XbmJYvRX9r93z6GQqOv5FQy1JhatwefxhKdyhkDEHsqELO0XDqnDnmgxkEEU-lHYSVGz-iDlUZOUYTTCtxsPDmBIXOMuwp0UydJphO36qRQaDyEjHNsYKLj5KVvjDHS8Gw1FhbFvsoUrBHre4hLY9Pa5meatV_k\",\"e\":\"AQAB\"," +
                    "\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"192\"}" +
                "]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("188");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("188", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("194");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("194", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("190");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("190", equalTo(selected.get(0).getKeyId()));
    }

    @Test
    public void uniqueKidTestsMicrosoftJwksEndpoint() throws JoseException
    {
        // JSON content from https://login.windows.net/common/discovery/keys on Jan 7, 2015
        // (n is base64 rather than base64url but we can still consume it http://www.ietf.org/mail-archive/web/jose/current/msg04807.html
        String json = "{\"keys\":[" +
                "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"kriMPdmBvx68skT8-mPAB3BseeA\",\"x5t\":\"kriMPdmBvx68skT8-mPAB3BseeA\",\"n\":\"kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuw==\",\"e\":\"AQAB\",\"x5c\":[\"MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ\"]}," +
                "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"x5t\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"n\":\"vIqz+4+ER/vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq+RtwN1Vs/z57hO82kkzL+cQHZX3bMJD+GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW/EW/P+C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T/Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp/KAS/qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3+T+IAbsk1wRtWDndhO6s1Os+dck5TzyZ/dNOhfXgelixLUQ==\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"]}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("kriMPdmBvx68skT8-mPAB3BseeA");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("kriMPdmBvx68skT8-mPAB3BseeA", equalTo(selected.get(0).getKeyId()));

        // check some x5x stuff here too 'cause MS includes x5t and x5c
        PublicJsonWebKey publicJsonWebKey = (PublicJsonWebKey) selected.get(0);
        String x5t = X509Util.x5t(publicJsonWebKey.getLeafCertificate());
        assertThat(x5t, equalTo("kriMPdmBvx68skT8-mPAB3BseeA"));
        assertThat(x5t, equalTo(publicJsonWebKey.getX509CertificateSha1Thumbprint()));
        assertNull(publicJsonWebKey.getX509CertificateSha256Thumbprint());
        assertNull(publicJsonWebKey.getX509Url());

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("MnC_VZcATfM5pOYiJHMba9goEKY");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("MnC_VZcATfM5pOYiJHMba9goEKY", equalTo(selected.get(0).getKeyId()));
        publicJsonWebKey = (PublicJsonWebKey) selected.get(0);
        x5t = X509Util.x5t(publicJsonWebKey.getLeafCertificate());
        assertThat(x5t, equalTo("MnC_VZcATfM5pOYiJHMba9goEKY"));
        assertThat(x5t, equalTo(publicJsonWebKey.getX509CertificateSha1Thumbprint()));
        assertNull(publicJsonWebKey.getX509CertificateSha256Thumbprint());
        assertNull(publicJsonWebKey.getX509Url());

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setX509CertSha1ThumbprintHeaderValue("MnC_VZcATfM5pOYiJHMba9goEKY");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("MnC_VZcATfM5pOYiJHMba9goEKY", equalTo(selected.get(0).getKeyId()));
        publicJsonWebKey = (PublicJsonWebKey) selected.get(0);
        x5t = X509Util.x5t(publicJsonWebKey.getLeafCertificate());
        assertThat(x5t, equalTo("MnC_VZcATfM5pOYiJHMba9goEKY"));
        assertThat(x5t, equalTo(publicJsonWebKey.getX509CertificateSha1Thumbprint()));
        assertNull(publicJsonWebKey.getX509CertificateSha256Thumbprint());
        assertNull(publicJsonWebKey.getX509Url());

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setX509CertSha1ThumbprintHeaderValue("kriMPdmBvx68skT8-mPAB3BseeA");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("kriMPdmBvx68skT8-mPAB3BseeA", equalTo(selected.get(0).getKeyId()));
        publicJsonWebKey = (PublicJsonWebKey) selected.get(0);
        x5t = X509Util.x5t(publicJsonWebKey.getLeafCertificate());
        assertThat(x5t, equalTo("kriMPdmBvx68skT8-mPAB3BseeA"));
        assertThat(x5t, equalTo(publicJsonWebKey.getX509CertificateSha1Thumbprint()));
        assertNull(publicJsonWebKey.getX509CertificateSha256Thumbprint());
        assertNull(publicJsonWebKey.getX509Url());
    }

    @Test
    public void uniqueKidTestsGluuJwksEndpoint() throws JoseException
    {
        // JSON content from https://seed.gluu.org/oxauth/seam/resource/restv1/oxauth/jwks on Jan 7, 2015
        // the "alg": "EC" isn't right, IMHO but makes a nice test case I suppose   http://www.ietf.org/mail-archive/web/jose/current/msg04783.html
        String json = "{\"keys\": [\n" +
                "    {\n" +
                "        \"kty\": \"RSA\",\n" +
                "        \"kid\": \"1\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"RS256\",\n" +
                "        \"n\": \"AJYQhwMG7-PCPzmp-E8_Jz8zGVuIA0upMUrqOLa9lpcduLXlpgv_g525DU8vJ34GqNgYcsjNw2dvV03cWSU8VguWSC5ijHfhzf3cSbEJTcBOfCpbir8hRgAOkU4gqSf8rXTugyJ6jw4wiMEnLlk8j18chGQvn-bqKDw9aEqg_ssxz3f0yO_p4bl5_9n5FGQHGyZYv6B_PsAHZkm_DNDu7Wa_vfv8vnq3u_38uf4WC6S5cMR15B74Ja0ylR498h23E2riz9o7X2rLsL26JLUWSfjDw-twYqF4jt6oCGDIIv4zCYdpim-2L5qKMkASPAbWs_KfXIIhJuLohrpzOaqZh_k\",\n" +
                "        \"e\": \"AQAB\",\n" +
                "        \"x5c\": [\"MIIDMDCCAhgCgYBDSFLKDmTPKXlpVPR8EuhbSUGCgd2okr\\/tL7sW9nlr6oKpNovrEFUL0YkqT59dNG7zldXJWY92VQDJSmpeRX6TX74efV1prpF4Y9sW5y0iu9njcAxE2zDBCM6rGWNf+WWajOajuYkbqEfOOl1PikQkFCliIUdDYSvId6Sco05tsjANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMloXDTE0MDIxMTIxMjQxMlowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJYQhwMG7+PCPzmp+E8\\/Jz8zGVuIA0upMUrqOLa9lpcduLXlpgv\\/g525DU8vJ34GqNgYcsjNw2dvV03cWSU8VguWSC5ijHfhzf3cSbEJTcBOfCpbir8hRgAOkU4gqSf8rXTugyJ6jw4wiMEnLlk8j18chGQvn+bqKDw9aEqg\\/ssxz3f0yO\\/p4bl5\\/9n5FGQHGyZYv6B\\/PsAHZkm\\/DNDu7Wa\\/vfv8vnq3u\\/38uf4WC6S5cMR15B74Ja0ylR498h23E2riz9o7X2rLsL26JLUWSfjDw+twYqF4jt6oCGDIIv4zCYdpim+2L5qKMkASPAbWs\\/KfXIIhJuLohrpzOaqZh\\/kCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAA1c5yds2m89XnhEr+WFE8APdkveJDxa+p7R5TSR924+nq4v11UPzSqkpn+Nk\\/QYM6uUBH1Z0axBgrFy\\/auunXbtDfm\\/HzQkTx+Dlq4DgcTzUKUC\\/3ObfVQCEFCaKfbtg+PTM7QytJgeoGPbjWneIvgis3zvmCULknGt\\/7CYh2URAaBkWitLBuYa0yCnPSfajNpnMrOEPBElsU0lC+ka4N\\/C\\/v5nvkfnneMDnr8UMV2OkRv+BDyoUg5HWgtWNV7AE0I7I89aVmLxWGp0tWwnZxbfbfGChGEhHHgx0eri9L4+Hd9l5ZP1csuojHoHHcMSmaT2\\/4edG4Eyxm6C2GPrCGg==\"]\n" +
                "    },\n" +
                "    {\n" +
                "        \"kty\": \"RSA\",\n" +
                "        \"kid\": \"2\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"RS384\",\n" +
                "        \"n\": \"ALs6oVo2LGaBb39Z8loTmhiZhZPq0wbfTpvhFjFoEXJRTLlucPYftbV3g_aTmUiL_Pz919nWCj-X2WOtE3g7du823qJqX8ieas_c7ehZcG8D-pxxUipRqBDX76Bw6jZ00QtEcc89MU4GJaROHcm0L8iQMkSZgIFN8u5_ZvtQzWyynXTmHve0nNMoVhTn1nrxK_dGotCDkzJZ3ph7Rjq5smxjoPGrzzeesCo9c_3edrD4jiFkDUlEOabvqfhTeX1K_X3HO-LHBBI2QxvP7U1MarxyP8TMsIQjjR1ggGNkdv4gtTK5AixjHlQYswQragzBWQ5dTrUNl366NNpYTD3-o3M\",\n" +
                "        \"e\": \"AQAB\",\n" +
                "        \"x5c\": [\"MIIDMDCCAhgCgYBmLjh1H5nHW466kS5EPsNmi+92mYsiRZ4Al+GOLr\\/067Dpy\\/qwiSHVcIsY0pPCORukIvwxf2CUHeKRg7HDD87jddENjlcEpUDNT9EjxixymSbrQEerPliD69MCTqGp6KyfRrf44cuEQFDdSQbYW+b25Ivms33sLim+\\/5uENE7MbjANBgkqhkiG9w0BAQwFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxM1oXDTE0MDIxMTIxMjQxM1owHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALs6oVo2LGaBb39Z8loTmhiZhZPq0wbfTpvhFjFoEXJRTLlucPYftbV3g\\/aTmUiL\\/Pz919nWCj+X2WOtE3g7du823qJqX8ieas\\/c7ehZcG8D+pxxUipRqBDX76Bw6jZ00QtEcc89MU4GJaROHcm0L8iQMkSZgIFN8u5\\/ZvtQzWyynXTmHve0nNMoVhTn1nrxK\\/dGotCDkzJZ3ph7Rjq5smxjoPGrzzeesCo9c\\/3edrD4jiFkDUlEOabvqfhTeX1K\\/X3HO+LHBBI2QxvP7U1MarxyP8TMsIQjjR1ggGNkdv4gtTK5AixjHlQYswQragzBWQ5dTrUNl366NNpYTD3+o3MCAwEAATANBgkqhkiG9w0BAQwFAAOCAQEAS7rNA06jrBPCLMuUq38jlHolnPHQxS1Qg0aUUCNy955AMnoh4tF60ejIxIwiZIXZdWBR0cIDxV+8Cy3WYj4a8FDQnntVR0dREfGQyICf0v5reEenSj2u2DUHgCpwFbpmrh9UTjg0swU9G06LV+q\\/arDq+ejK9Wty8fWBw7RSpx3s5nq7xuA+TY4wqGTtIdPAI1q4oWOHn0x65FV6Mwv3Lis8gSXIvBhzjkAIh6PXK7YMic43sR6MGOKCJ3iO5bqW2kSJ0KQXOv6nxUwrs9k2dgrTxdUwNycZEYiQEiXK\\/sPHIhqEmRZK6H00dLz\\/99K4ZLm17YeF+7g4Sk0ZkMarpw==\"]\n" +
                "    },\n" +
                "    {\n" +
                "        \"kty\": \"RSA\",\n" +
                "        \"kid\": \"3\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"RS512\",\n" +
                "        \"n\": \"AK3SFO9Q0jJP1-n2ys7yyP70r149_EQ1z0EfgIg2qpAMXcuyDIWu-dqD05fkicN2izHAf463LydeRUXWAc058F-mYw8y69qcZyDxnqYu_IlmK77tDgE-oilPVF_JW3WMXAl3MHvhAQwc-2q2lLbs3qa6BqpZgXofiJdURaRS990qO1fqYm1ihT8hmq8WQmXbDS_0-L4sP3O8cK9FXWhWqtfC1yo0Ziv8OSQ3h8dYRFAupqESRpe3EzV5DICdHAdBBrSkLyfPTLIzavfCkhI4zB6VrxLF4l1yTo7ucfnobIUaiNEvwVwkytLrNM4HPk4dO8H0woEomqj4QzIPkUGLxLc\",\n" +
                "        \"e\": \"AQAB\",\n" +
                "        \"x5c\": [\"MIIDMDCCAhgCgYA6qJ8lNNfbB0VhX2UZLXLizoC1BCPEc2W25\\/hJKay\\/GXVMIA+42AvUqWSonkwDALudfWbPVR3vOqB8iq4O75aaGiEAw6roiOHHRVTCZm1PCH+TlGh+jATybe83cBtCGTmvt81Or4q0NK\\/sJ3hi3e\\/ds4IPn3eWScd1lhVUzIj2uDANBgkqhkiG9w0BAQ0FADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxM1oXDTE0MDIxMTIxMjQxM1owHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK3SFO9Q0jJP1+n2ys7yyP70r149\\/EQ1z0EfgIg2qpAMXcuyDIWu+dqD05fkicN2izHAf463LydeRUXWAc058F+mYw8y69qcZyDxnqYu\\/IlmK77tDgE+oilPVF\\/JW3WMXAl3MHvhAQwc+2q2lLbs3qa6BqpZgXofiJdURaRS990qO1fqYm1ihT8hmq8WQmXbDS\\/0+L4sP3O8cK9FXWhWqtfC1yo0Ziv8OSQ3h8dYRFAupqESRpe3EzV5DICdHAdBBrSkLyfPTLIzavfCkhI4zB6VrxLF4l1yTo7ucfnobIUaiNEvwVwkytLrNM4HPk4dO8H0woEomqj4QzIPkUGLxLcCAwEAATANBgkqhkiG9w0BAQ0FAAOCAQEASyqKmhz7o5VjB5gKSBaLw9yqNo8zruYizkLKhUxzAdna6qz73ONAdXtrdok79Qpio2nlvyPgspF9rYKgwxguvHpTOkdCZ3LNPF4QLsn3I0vs3gr8+oXhXbA58kqsBSAyt54HDTa7Zh8c\\/G1u5W\\/0+lsgCwtMSzeISnNrqY3a3K97Uy6OoxDqWk8t4W1OgtYhi6wiq7BGQ9xg7QlwMrVNc165ixgaW46\\/tpafONG7+WFaWnzROPHrh6rSv4diz8bd7MqDDVLB2q\\/QolzWTtxHSgkFu1t5dNEQznJI5Ay\\/txPKgRNiv3EhD8fv9EKsip1epKtsP5Il6mLktPBjZMHjMg==\"]\n" +
                "    },\n" +
                "    {\n" +
                "        \"kty\": \"EC\",\n" +
                "        \"kid\": \"4\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"EC\",\n" +
                "        \"crv\": \"P-256\",\n" +
                "        \"x\": \"eZXWiRe0I3TvHPXiGnvO944gjF1o4UmitH2CVwYIrPg\",\n" +
                "        \"y\": \"AKFNss7S35tOsp5iY7-YuLGs2cLrTKFk80JvgVzMPHQ3\",\n" +
                "        \"x5c\": [\"MIIBpDCCAUoCgYBCs6x21IvwVHFgJxiRegyHdSiEHFur9Wj2qM5oNkv6sFbbC75L849qCgMEzdtqIhCiCnFg6PaQdswHkcclXix+y0sycyIM6l429faY3jz5eQs5SYwXYkENStzTZBsWK6u7bPiV3HvjnIv+r1af8nvO5F0tiH0TC+auDj9FgRmYljAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMVoXDTE0MDIxMTIxMjQxMVowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmV1okXtCN07xz14hp7zveOIIxdaOFJorR9glcGCKz4oU2yztLfm06ynmJjv5i4sazZwutMoWTzQm+BXMw8dDcwCgYIKoZIzj0EAwIDSAAwRQIhAI4aRAoTVm3was6UimA1lFL2RId+t\\/fExaviosXNKg\\/IAiBpZB4XXcnQISwauSJ1hXNnSEcONXdqvO5gDHu+X7QHLg==\"]\n" +
                "    },\n" +
                "    {\n" +
                "        \"kty\": \"EC\",\n" +
                "        \"kid\": \"5\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"EC\",\n" +
                "        \"crv\": \"P-384\",\n" +
                "        \"x\": \"XGp9ovRmtaBjlZKGI1XDBUB6F3d4Xov4JFKUCaeVjMD0_GAp20IB_wZz6howe3yi\",\n" +
                "        \"y\": \"Vhy6zh3KOkDqSA5WP6BtDyS9CZR7RoCCWfwymBB3HIBIR_yl32hnSYXtlwEr2EoK\",\n" +
                "        \"x5c\": [\"MIIB4zCCAWgCgYEA9v7jYfmKYNePYWQt6M8BQsvb4swqpVEYulCJq8bOKuhz5\\/VgM8J8lGaClDRhY6msrtW16kRbZvnMvgKNBJ52TXGKtEFylMzDQ4k\\/HYGb1w7FwlXVyv3TScFNm9JnfsMe7ecOcanRFn+hYjiZdEcTB85wLvpKRDlkpuIf0khB8iMwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0xMzAyMTEyMTI0MTFaFw0xNDAyMTEyMTI0MTFaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARcan2i9Ga1oGOVkoYjVcMFQHoXd3hei\\/gkUpQJp5WMwPT8YCnbQgH\\/BnPqGjB7fKJWHLrOHco6QOpIDlY\\/oG0PJL0JlHtGgIJZ\\/DKYEHccgEhH\\/KXfaGdJhe2XASvYSgowCgYIKoZIzj0EAwIDaQAwZgIxAOV6rC\\/muVarcSXaP9Z7Pn7aI3o5fixoVx6E\\/xYTOg+H10FMsluIdahjt90fNJYiYAIxAO+IHenKHe2xr8RpphzqWnAexswcEI6A3drp1f24Z8XtTJHNIHAVP6wr88oz5+eFoQ==\"]\n" +
                "    },\n" +
                "    {\n" +
                "        \"kty\": \"EC\",\n" +
                "        \"kid\": \"6\",\n" +
                "        \"use\": \"sig\",\n" +
                "        \"alg\": \"EC\",\n" +
                "        \"crv\": \"P-521\",\n" +
                "        \"x\": \"KrVaPTvvYmUUSf_1UpwJt_Lg9UT-8OHD_AUd-d7-Q8Rfs4t-lTJ5KEyjbfMzTHsvNulWftuaMH6Ap3l5vbDb2nQ\",\n" +
                "        \"y\": \"AIxSEGvlKlWZiN_Rc3VjBs5oVB5l-JfCZHm2LyZpOxAzWrpjHlK121H2ZngM8Ra8ggKa64hEMDE1fMV__C_EZv9m\",\n" +
                "        \"x5c\": [\"MIICLDCCAY0CgYAcLY90WqvtOS1H1zyF0jrrHT549yccB4rk61J96JlOnRTbuTq7wWWgOm6csS+19GMRIIDk5njc6M50WUeCcFEURy9wmZKAW3\\/PgOgnPydjnvBIIofOfZOVeaLjji64h7Ju\\/Ur8Ki28sN5xeyz5iGhqst1CJ0RVBAbpT4IN2szemTAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTEzMDIxMTIxMjQxMVoXDTE0MDIxMTIxMjQxMVowHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEACq1Wj0772JlFEn\\/9VKcCbfy4PVE\\/vDhw\\/wFHfne\\/kPEX7OLfpUyeShMo23zM0x7LzbpVn7bmjB+gKd5eb2w29p0AIxSEGvlKlWZiN\\/Rc3VjBs5oVB5l+JfCZHm2LyZpOxAzWrpjHlK121H2ZngM8Ra8ggKa64hEMDE1fMV\\/\\/C\\/EZv9mMAoGCCqGSM49BAMCA4GMADCBiAJCAb+BYADga2su9Sejzgbfz4lrSPt1l7PWeyDXtTGqa8yvIf4f3Hudp272WeXxeBpL\\/7EFtho8CvG8zhvrp7bC+E84AkIBv3V6seORxzsO5hv1mtAKIPdFmePIrKrGFqa7ESR56DZxVYeJ5GHi1gU4LJdGcUYDpz0GDqznxAmvA3AimrwAWUk=\"]\n" +
                "    }\n" +
                "]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("1");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("1", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA384);
        jws.setKeyIdHeaderValue("2");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("2", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setKeyIdHeaderValue("3");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("3", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("4");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("4", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
        jws.setKeyIdHeaderValue("5");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("5", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512);
        jws.setKeyIdHeaderValue("6");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("6", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setX509CertSha256ThumbprintHeaderValue("Xm5kcmgZp3dZmZc_-K31CzStJl5pH3QjRp45D8uhinM");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("3", equalTo(selected.get(0).getKeyId()));


        SimpleJwkFilter filter = new SimpleJwkFilter();
        filter.setKid("3", SimpleJwkFilter.VALUE_REQUIRED);
        JsonWebKey three = filter.filter(jsonWebKeys).iterator().next();
        PublicJsonWebKey publicThree = (PublicJsonWebKey) three;
        X509Certificate leafCertificate = publicThree.getLeafCertificate();

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setX509CertSha256ThumbprintHeaderValue(leafCertificate);
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("3", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setX509CertSha1ThumbprintHeaderValue(leafCertificate);
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("3", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
        jws.setX509CertSha256ThumbprintHeaderValue("NOPENOPE3dZmZc_-K31CzStJl5pH3QjRp45D8uhinM");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertTrue(selected.isEmpty());
    }

    @Test
    public void uniqueKidTestFRJwksEndpoint() throws JoseException
    {
        // JSON content from https://demo.forgerock.com:8443/openam/oauth2/connect/jwk_uri on Jan 8, 2015
        String json = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"fb301b61-9b8a-4c34-9212-5d6fb9df1a57\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"AK0kHP1O-RgdgLSoWxkuaYoi5Jic6hLKeuKw8WzCfsQ68ntBDf6tVOTn_kZA7Gjf4oJAL1dXLlxIEy-kZWnxT3FF-0MQ4WQYbGBfaW8LTM4uAOLLvYZ8SIVEXmxhJsSlvaiTWCbNFaOfiII8bhFp4551YB07NfpquUGEwOxOmci_\",\"e\":\"AQAB\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("fb301b61-9b8a-4c34-9212-5d6fb9df1a57");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("fb301b61-9b8a-4c34-9212-5d6fb9df1a57", equalTo(selected.get(0).getKeyId()));
    }


    @Test
    public void uniqueKidTestMiterJwksEndpoint() throws JoseException
    {
        // JSON content from https://mitreid.org/jwk on Jan 8, 2015
        String json = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"n\":\"23zs5r8PQKpsKeoUd2Bjz3TJkUljWqMD8X98SaIb1LE7dCQzi9jwO58FGL0ieY1Dfnr9-g1iiY8sNzV-byawK98W9yFiopaghfoKtxXgUD8pi0fLPeWmAkntjn28Z_WZvvA265ELbBhphPXEJcFhdzUfgESHVuqFMEqp1pB-CP0\"," +
                "\"kty\":\"RSA\",\"kid\":\"rsa1\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("rsa1");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("rsa1", equalTo(selected.get(0).getKeyId()));
    }

    @Test
    public void uniqueKidTestNriPhpJwksEndpoint() throws JoseException
    {
        // JSON content from https://connect.openid4.us/connect4us.jwk on Jan 8, 2015
        String json = "{\n" +
                " \"keys\":[\n" +
                "  {\n" +
                "   \"kty\":\"RSA\",\n" +
                "   \"n\":\"tf_sB4M0sHearRLzz1q1JRgRdRnwk0lz-IcVDFlpp2dtDVyA-ZM8Tu1swp7upaTNykf7cp3Ne_6uW3JiKvRMDdNdvHWCzDHmbmZWGdnFF9Ve-D1cUxj4ETVpUM7AIXWbGs34fUNYl3Xzc4baSyvYbc3h6iz8AIdb_1bQLxJsHBi-ydg3NMJItgQJqBiwCmQYCOnJlekR-Ga2a5XlIx46Wsj3Pz0t0dzM8gVSU9fU3QrKKzDFCoFHTgig1YZNNW5W2H6QwANL5h-nbgre5sWmDmdnfiU6Pj5GOQDmp__rweinph8OAFNF6jVqrRZ3QJEmMnO42naWOsxV2FAUXafksQ\",\n" +
                "   \"e\":\"AQAB\",\n" +
                "   \"kid\":\"ABOP-00\"\n" +
                "  }\n" +
                " ]\n" +
                "}\n";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA384);
        jws.setKeyIdHeaderValue("ABOP-00");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("ABOP-00", equalTo(selected.get(0).getKeyId()));
    }

    @Test
    public void noKidTestNovJwksEndpoint() throws JoseException
    {
        // JSON content from https://connect-op.herokuapp.com/jwks.json on Jan 8, 2015
        String json = "{\"keys\":[" +
                "{\"kty\":\"RSA\"," +
                "\"e\":\"AQAB\"," +
                "\"n\":\"pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE-Yopfu3B58QlgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JBqaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9RfzT87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw\"" +
                ",\"use\":\"sig\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256));
        jws.setCompactSerialization("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2Nvbm5lY3Qtb3AuaGVyb2t1YXBwLmNvbSIsInN1YiI6IjZiOTYyYzk1Nzk4NThkNzJjNjY0M2FiZjhkN2E2ZWJjIiwiYXVkIjoiZGIwZTdmYTNmNmQwN2ZhMjYzMjZhNzE4NjQwMGVhOTEiLCJleHAiOjE0MjA3NTI0NzAsImlhdCI6MTQyMDczMDg3MCwibm9uY2UiOiJiOGU1OTlhM2JkYTRkNDExYzhiMDc0OGM1MGQwZjQxNyJ9.FNyq7K90vW7eLmsjzUPQ8eTnTreOWXVt_WKyqS686_D_kZ9tl3_uE3tKBw004XyFwMYd-4zWhvXaDPkhFGJ6BPy_woxnQdiTobNE-jyQscp6-6keg3QRkjV-Te7F48Pyfzl-lwvzhb76ygjuv7v_1Nf49fHZb-SiQ2KmapabHpIfVvuqTQ_MZjU613XJIW0tMqFv4__fgaZD-JU6qCkVbkXpvIMg_tZDafsipJ6ZYH9_9JuXQqjzmsM6vHN53MiQZaDtwb6nLDFln6YPqmVPXJV6SLvM_vn0g5w6jvmfsPGZL-xo-iqWbYtnMK-dX4HmnLpK4JVba_OnA9NQfj2DRQ");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        JsonWebKey jsonWebKey = selected.get(0);
        jws.setKey(jsonWebKey.getKey());
        assertTrue(jws.verifySignature());
    }

    @Test
    public void noKidTestRyoItoJwksEndpoint() throws JoseException
    {
        // JSON content from https://openidconnect.info/jwk/jwk.json on Jan 8, 2015
        String json = "{\"keys\":[" +
                "{\"alg\":\"RSA\"" +  // missing kty and misused alg
                ",\"mod\":\"4ZLcBYTH4S3b80iEkDKTAmLvNM3XkqgdQoLPtNgNoilmHD1wian5_EDl2IvwAJRug9I0TnhVuMZW3ylhsPxus3Iu70nCQbOdsoBCobNzm6RaLUsz6LjRa2mvLMHeG1CP5rGWiv5GwBU8DNuUf_uPWXMe9K3i3E27nm4NnwDcOMPETpr6PLB2h4iXsHrKGLIFPdoPx_TIcrbj7RR9vWtrkj1pHt2OnJy5cFmXXRc77SZw0qRouVD0cqiS0XPHTaoFgmFr1x7NdbENxMJZJ-VPaIqN0ht2tFX5oOCClhNjBTKc2U-c-b32ETtUnNUu1kHafS-V0qsobmy-Cq_gyyQY2w\"," +
                "\"exp\":\"AQAB\"," +
                "\"user\":\"sig\"}]}"; // user should be use

        JsonWebKeySet jwks = new JsonWebKeySet(json);
        assertTrue(jwks.getJsonWebKeys().isEmpty()); // their json jwk is just broken  http://www.ietf.org/mail-archive/web/jose/current/msg04783.html
    }

    @Test
    public void uniqueKidAndX5tTestThinktectureJwksEndpoint() throws JoseException
    {
        // JSON content from https://identity.thinktecture.com/.well-known/jwks on Jan 8, 2015
        //  n is regular base64 rather than base64url http://www.ietf.org/mail-archive/web/jose/current/msg04783.html
        String json = "{\"keys\":[" +
                "{\"kty\":\"RSA\"," +
                "\"use\":\"sig\"," +
                "\"kid\":\"a3rMUgMFv9tPclLa6yF3zAkfquE\"," +
                "\"x5t\":\"a3rMUgMFv9tPclLa6yF3zAkfquE\"," +
                "\"e\":\"AQAB\"," +
                "\"n\":\"qnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFw==\"," +
                "\"x5c\":[\"MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrNA6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEFBQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCHQUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pivqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmbrb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xGvQb3VHSTVVbeei0CfXoW6iz1\"]}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();


        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("a3rMUgMFv9tPclLa6yF3zAkfquE");
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("a3rMUgMFv9tPclLa6yF3zAkfquE", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setX509CertSha1ThumbprintHeaderValue("a3rMUgMFv9tPclLa6yF3zAkfquE");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        JsonWebKey jsonWebKey = selected.get(0);
        assertThat("a3rMUgMFv9tPclLa6yF3zAkfquE", equalTo(jsonWebKey.getKeyId()));
        PublicJsonWebKey publicJsonWebKey = (PublicJsonWebKey) jsonWebKey;
        assertThat("a3rMUgMFv9tPclLa6yF3zAkfquE", equalTo(publicJsonWebKey.getX509CertificateSha1Thumbprint()));
    }

    @Test
    public void notUniqueKidSoDisambiguateByAlgUseKtyTests() throws JoseException
    {
        // JSON content from a PingFederate JWKS endpoint modified by hand to fake up some semi-plausible cases (same kid used for different key types and algs)
        String json = "{" +
                "  \"keys\": [" +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9ou3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\"," +
                "      \"y\": \"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrvP2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\"," +
                "      \"crv\": \"P-521\"" +
                "      \"alg\": \"ES521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\"," +
                "      \"y\": \"Bt0HwjlM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\"," +
                "      \"crv\": \"P-384\"" +
                "      \"alg\": \"ES384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\"," +
                "      \"y\": \"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\"," +
                "      \"crv\": \"P-256\"" +
                "      \"alg\": \"ES256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"Aeu8Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNae81RujWu3aSEWoX1aAVRh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\"," +
                "      \"y\": \"AOlx2rRLBLI3nh3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92ADYJBItvRdKcBk-BYb4Cewma7KtNuIK8zZ2HEen6d\"," +
                "      \"crv\": \"P-521\"" +
                "      \"alg\": \"ES521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"gcqegh2wqsLgmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwTlhNMc4V8FO01Jt\"," +
                "      \"y\": \"-bO4V5xtasOgWsrCGs_bydqT0o3O29cA-5Sl7aqSfB7Z5-N3Dki5Ed2RZEU0Q7g0\"," +
                "      \"crv\": \"P-384\"" +
                "      \"alg\": \"ES384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"6elUcv15VpXlU995KVHZ3Jx6V8Cq7rCoodyIaXbQxS8\"," +
                "      \"y\": \"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu8\"," +
                "      \"crv\": \"P-256\"" +
                "      \"alg\": \"ES256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"wbcVJs-T_yP6TEWmdAqTo3qFsdtpffUEqVbxtaWr-PiXs4DTWtig6kYO1Hwim0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a1V3fov09BmfODE7MRVEqmZXHRxGUxXLGZn294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVHUP_xo5vRxQ0tTO0z1YHfjNNpycLlCNOoxbuN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGwHIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVccvz0SD7es-\"," +
                "      \"y\": \"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8UdiLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T\"," +
                "      \"crv\": \"P-521\"" +
                "      \"alg\": \"ES521\"" +

                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"cLP7G_dHWU7CGlB3h2Rt-yr4cuT2-ybk6Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\"," +
                "      \"y\": \"-OzAuuaPViw3my3UAE3WiXOYlaa5MYz7dbMBSZjZhretKm118itVnCI_WRAkWMa7\"," +
                "      \"crv\": \"P-384\"" +
                "      \"alg\": \"ES384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"IUk0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnqVZ5DTmI\"," +
                "      \"y\": \"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\"," +
                "      \"crv\": \"P-256\"" +
                "      \"alg\": \"ES256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"lMRL3ng10Ahvh2ILcpEiKNi31ykHP8Iq7AENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGlKiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lKD6q7_UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtMmZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysarzW_mUX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\"," +
                "      \"e\": \"AQAB\"" +
                "    }" +
                "  ]" +
                "}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("1");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("1", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("2");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        assertThat("2", equalTo(selected.get(0).getKeyId()));
        JsonWebKey jsonWebKey = selected.get(0);
        EllipticCurveJsonWebKey ellipticCurveJsonWebKey = (EllipticCurveJsonWebKey) jsonWebKey;
        assertThat("2", equalTo(jsonWebKey.getKeyId()));
        assertThat(EllipticCurves.P_256, equalTo(ellipticCurveJsonWebKey.getCurveName()));
    }

    @Test
    public void notUniqueKidSoDisambiguateByUseKtyTests() throws JoseException
    {
        // JSON content from a PingFederate JWKS endpoint modified by hand to fake up some semi-plausible cases (same kid used for different key types - no algs so crv is used on ECs)
        String json = "{" +
                "  \"keys\": [" +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9ou3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\"," +
                "      \"y\": \"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrvP2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\"," +
                "      \"y\": \"Bt0HwjlM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\"," +
                "      \"y\": \"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"3\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"Aeu8Jbm9XTwhwHcq19BthU6VIz4HU7qDG7CNae81RujWu3aSEWoX1aAVRh_ZMABfMKWCtXvhh2FEpSAcQRiKilfG\"," +
                "      \"y\": \"AOlx2rRLBLI3nh3eAlWI1ciFKWaw-6XEJw4o6nLXHRBVo92ADYJBItvRdKcBk-BYb4Cewma7KtNuIK8zZ2HEen6d\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"gcqegh2wqsLgmikkGF1137rVf5QPhJb0hF7zwWNwSM5jyWwfwTlhNMc4V8FO01Jt\"," +
                "      \"y\": \"-bO4V5xtasOgWsrCGs_bydqT0o3O29cA-5Sl7aqSfB7Z5-N3Dki5Ed2RZEU0Q7g0\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"6elUcv15VpXlU995KVHZ3Jx6V8Cq7rCoodyIaXbQxS8\"," +
                "      \"y\": \"mHnmwkt-jhxWKjzx75egxVx2B25QiRzi5l0jNDF9hu8\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"2\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"wbcVJs-T_yP6TEWmdAqTo3qFsdtpffUEqVbxtaWr-PiXs4DTWtig6kYO1Hwim0j780f6pBgWTKAOBhGm4e3RQH86cGA-kC6uD1931OLM1tcRhoaEsz9jrGWn31dSLBX9H_4YqR-a1V3fov09BmfODE7MRVEqmZXHRxGUxXLGZn294LxZDRGEKwflTo3QZDG-Yirzf4UnbPERmSJsz6KE5FkO1k1YWCh1JnPlE9suQZC6OXIFRYwVHUP_xo5vRxQ0tTO0z1YHfjNNpycLlCNOoxbuN3f7_vUD08U2v5YnXs8DPGCO_nG0gXDzeioqVDa2cvDKhOtSugbI_nVtPZgWSQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AeRkafLScUO4UclozSPJpxJDknmB_SM70lA4MLGY9AGwHIu1tTl-x9WjttYZNrQ6eE0bAWGb_0jgVccvz0SD7es-\"," +
                "      \"y\": \"AdIP5LQzH3oNFTZGO-CVnkvD35F3Cd611zYjts5frAeqlxVbB_l8UdiLFqIJVuVLoi-kFJ9htMBIo1b2-dKdhI5T\"," +
                "      \"crv\": \"P-521\"" +

                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"cLP7G_dHWU7CGlB3h2Rt-yr4cuT2-ybk6Aq5zoBmzUo5jNrQR_IvrllfvdVfF1ub\"," +
                "      \"y\": \"-OzAuuaPViw3my3UAE3WiXOYlaa5MYz7dbMBSZjZhretKm118itVnCI_WRAkWMa7\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"IUk0VFdRVnVVmdCfZxREU0pXmUk9fub4JVnqVZ5DTmI\"," +
                "      \"y\": \"DNr82q7z1vfvIjp5a73t1yKg2vhcUDKqdsKh_FFbBZs\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"kid\": \"1\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"lMRL3ng10Ahvh2ILcpEiKNi31ykHP8Iq7AENbwvsUzfag4ZBtid6RFBsfBMRrS_dGx1Ajjkpgj3igGlKiu0ZsSeu3zDK2e4apJGonxOQr7W2Bpv0bltU3bVRUb6i3-jv5sok33l2lKD6q7_UYRCmuo1ui2FGpwhorNVRFMe24HE895lvzGqDXUzsDKtMmZIt6Cj1WfJ68ZQ0gNByg-GVRtZ_BgZmyQwfTmPYxN_0uQ8usHz6kuSEysarzW_mUX1VEdzJ2dKBxmNwQlTW9v1UDvhUd2VXbGk1BvbJzFYL7z6GbxwhCynN-1bNb2rCFtRSI3UB2MgPbRkyjS97B7j34w\"," +
                "      \"e\": \"AQAB\"" +
                "    }" +
                "  ]" +
                "}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue("1");
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));

        assertThat("1", equalTo(selected.get(0).getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("2");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        JsonWebKey jsonWebKey = selected.get(0);
        EllipticCurveJsonWebKey ellipticCurveJsonWebKey = (EllipticCurveJsonWebKey) jsonWebKey;
        assertThat("2", equalTo(jsonWebKey.getKeyId()));
        assertThat(EllipticCurves.P_256, equalTo(ellipticCurveJsonWebKey.getCurveName()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512);
        jws.setKeyIdHeaderValue("2");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        jsonWebKey = selected.get(0);
        ellipticCurveJsonWebKey = (EllipticCurveJsonWebKey) jsonWebKey;
        assertThat("2", equalTo(jsonWebKey.getKeyId()));
        assertThat(EllipticCurves.P_521, equalTo(ellipticCurveJsonWebKey.getCurveName()));


        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
        jws.setKeyIdHeaderValue("2");
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
        jsonWebKey = selected.get(0);
        ellipticCurveJsonWebKey = (EllipticCurveJsonWebKey) jsonWebKey;
        assertThat("2", equalTo(jsonWebKey.getKeyId()));
        assertThat(EllipticCurves.P_384, equalTo(ellipticCurveJsonWebKey.getCurveName()));

        JsonWebKey selectedJwk = verificationJwkSelector.select(jws, jsonWebKeys);
        assertThat(selectedJwk.getKey(), equalTo(ellipticCurveJsonWebKey.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        assertNull(verificationJwkSelector.select(jws, jsonWebKeys));
    }

    @Test
    public void idtokenFromPf() throws Exception
    {
        // JWKS from a PingFederate JWKS endpoint along with a couple ID Tokens (JWTs) it issued
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhMDBrIn0." +
                "eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiUXhSYjF2Z2tpSE90MlZoNVdST0pQUiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5MzM4MiwiZXhwIjoxNDIxMDkzOTgyLCJub25jZSI6Im5hbmFuYW5hIiwiYWNyIjo" +
                "idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MjEwOTMzNzZ9." +
                "OlvyiduU_lZjcFHXchOzOptaBRt2XW_W2LATCPnfmi_mrfz5BsCvCGmTq6HCBBuOVF0BcbLA1h4ls3naPVu4YeWc1jkKFmlu5UwAdHP3fdUvAQdByyXDAxFgYIwl06EF-qpEX7r5_1D0OnrReq55n_SA-iqRync2nn5ZhkRoEj77E5yMFG93yRp4IP-WNZW3mZjkFPn" +
                "SCEHfRU0IBURfWkPzSkt5bKx8Vr-Oc1I5hFUyKyap8Ky17q_PoF-bHZG7MZ8B5Q5RvweVbdudain_yH3VAujDtqN_gu-7m1Vt6WdQpFIOGsVSpCK0-wtV3MvXzSKLk-5qwdVSI4GH5K_Q9g";
        String jwksJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"8a00r\",\"use\":\"sig\",\"x\":\"AZkOsR09YQeFcD6rhINHWAaAr8DMx9ndFzum50o5KLLUjqF7opKI7TxR5LP_4uUvG2jojF57xxWVwWi2otdETeI-\",\"y\":\"AadJxOSpjf_4VxRjTT_Fd" +
                "AtFX8Pw-CBpaoX-OQPPQ8o0kOrj5nzIltwnEORDldLFIkQQzgTXMzBnWyQurVHU5pUF\",\"crv\":\"P-521\"},{\"kty\":\"EC\",\"kid\":\"8a00q\",\"use\":\"sig\",\"x\":\"3n74sKXRbaBNw9qOGslnl-WcNCdC75cWo_UquiGUFKdDM3hudthy" +
                "wE5y0R6d2Li8\",\"y\":\"YbZ_0lregvTboKmUX7VE7eknQC1yETKUdHzt_YMX4zbTyOxgZL6A38AVfY8Q8HWd\",\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"8a00p\",\"use\":\"sig\",\"x\":\"S-EbFKVG-7pXjdgM9SPPw8rN3V8-2uX4" +
                "bNg4y8R7EhA\",\"y\":\"KTtyNGz9B9_QrkFf7mP90YiH6F40fAYfqpzQh8HG7tc\",\"crv\":\"P-256\"},{\"kty\":\"RSA\",\"kid\":\"8a00o\",\"use\":\"sig\",\"n\":\"kM-83p_Qaq-1FuxLHH6Y7jQeBT5MK9iHGB75Blnit8rMIcsns72Ls" +
                "1uhEYiyB3_icK7ibLr2_AHiIl7MnJBY2cCquuwiTccDM5AYUccdypliSlVeAL0MBa_0xfpvBJw8fB45wX6kJKftbQI8xjvFhqSIuGNyQOzFXnJ_mCBOLv-6Nzn79qWxh47mQ7NJk2wSYdFDsz0NNGjBA2VQ9U6weqL1viZ1sbzXr-bJWCjjEYmKC5k0sjGGXJuvMPEq" +
                "BY2q68kFXD3kiuslQ3tNS1j4d-IraadxpNVtedQ44-xM7MC-WFm2f5eO0LmJRzyipGNPkTer66q6MSEESguyhsoLNQ\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"8a00n\",\"use\":\"sig\",\"x\":\"ADoTal4nAvVCgicprEBBFOzNKUKVJl1P" +
                "h8sISl3Z3tz7TJZlQB485LJ3xil-EmWvqW1-sKFl7dY2YtrGUZvjGp0O\",\"y\":\"AXVB58hIK7buMZmRgDU4hrGvcVQLXa-77_F755OKIkuWP5IJ6GdjFvaRHfIbbHMp-whqjmRrlwfYPN1xmyCGSzpT\",\"crv\":\"P-521\"},{\"kty\":\"EC\"," +
                "\"kid\":\"8a00m\",\"use\":\"sig\",\"x\":\"5Y4xK9IBGJq5-E6QAVdpiqZb9Z-_tro_rX9TAUdWD3jiVS5N-blEnu5zWzoUoiJk\",\"y\":\"ZDFGBLBbiuvHLMOJ3DoOSRLU94uu5y3s03__HaaaLU04Efc4nGdY3vhTQ4kxEqVj\"," +
                "\"crv\":\"P-384\"},{\"kty\":\"EC\",\"kid\":\"8a00l\",\"use\":\"sig\",\"x\":\"CWzKLukg4yQzi4oM-2m9M-ClxbU4e6P9G_HRn9A0edI\",\"y\":\"UB1OL_eziV6lA5J0PiAuzoKQU_YbXojbjh0sfxtVlOU\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"RSA\",\"kid\":\"8a00k\",\"use\":\"sig\",\"n\":\"ux8LdF-7g3X1BlqglZUw36mqjd9P0JWfWxJYvR6pCFSyqLrETc-fL9_lTG3orohkGnEPe7G-BO65ldF44pYEe3eZzcEuEFtiO5W4_Jap1Z430vdYgC_nZtENIJDWlsGM9ev-cOld7By-" +
                "8l3-wAyuspOKZijWtx6K57VLajyUHBSmbUtaeCwHQOGyMOV1V-cskbTO2u_HrLOLLkSv9oZrznAwpx_paFHy-aAsdFhb7EiBzwqqHQButo3aT3DsR69gbW_Nmrf6tfkril6B3ePKV4od_5jowa6V3765K6v2L4NER7fuZ2hJVbIc0eJXY8tL3NlkBnjnmQ8DBWQR81A" +
                "yhw\",\"e\":\"AQAB\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256));
        jws.setCompactSerialization(jwt);
        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebKey selectedJwk = verificationJwkSelector.select(jws, jwks.getJsonWebKeys());
        jws.setKey(selectedJwk.getKey());
        assertTrue(jws.verifySignature());

        jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMDBsIn0." +
                "eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcHoxSHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJub25jZSI6ImZmcyIsImFjciI6InVybjp" +
                "vYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDIxMDkzMzc2fQ." +
                "gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ";
        jws = new JsonWebSignature();
        jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256));
        jws.setCompactSerialization(jwt);
        selectedJwk = verificationJwkSelector.select(jws, jwks.getJsonWebKeys());
        jws.setKey(selectedJwk.getKey());
        assertTrue(jws.verifySignature());
    }

    @Test
    public void noKids() throws JoseException
    {
        String json = "{" +
                "  \"keys\": [" +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"AAib8AfuP9X2esxxZXJUH0oggizKpaIhf9ou3taXkQ6-nNoUfZNHllwaQMWzkVSusHe_LiRLf-9MJ51grtFRCMeC\"," +
                "      \"y\": \"ARdAq_upn_rh4DRonyfopZbCdeJKhy7_jycKW9wceFFrvP2ZGC8uX1cH9IbEpcmHzXI2yAx3UZS8JiMueU6J_YEI\"," +
                "      \"crv\": \"P-521\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"wwxLXWB-6zA06R6hs2GZQMezXpsql8piHuuz2uy_p8cJ1UDBXEjIblC2g2K0jqVR\"," +
                "      \"y\": \"Bt0HwjlM4RoyCfq7DM9j34ujq_r45axa0S33YWLdQvHIwTj5bW1z81jqpPw0F_Xm\"," +
                "      \"crv\": \"P-384\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"use\": \"sig\"," +
                "      \"x\": \"9aKnpWa5Fnhvao2cWprEj4tpWCJpY06n2DsaxjJ6vbU\"," +
                "      \"y\": \"ZlAzvRY_PP0lTJ3nkxIP6HUW9KgzzxE4WWicXQuvf6w\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"RSA\"," +
                "      \"use\": \"sig\"," +
                "      \"n\": \"qqqF-eYSGLzU_ieAreTxa3Jj7zOy4uVKCpL6PeV5D85jHskPbaL7-SXzW6LlWSW6KUAW1Uwx_nohCZ7D5r24pW1tuQBnL20pfRs8gPpL28zsrK2SYg_AYyTJwmFTyYF5wfE8HZNGapF9-oHO794lSsWx_SpKQrH_vH_yqo8Bv_06Kf730VWIuREyW1kQS7sz56Aae5eH5oBnC45U4GqvshYLzd7CUvPNJWU7pumq_rzlr_MSMHjJs49CHXtqpezQgQvxQWfaOi691yrgLRl1QcrOqXwHNimrR1IOQyXx6_6isXLvGifZup48GmpzWQWyJ4t4Ud95ugc1HLeNlkHtBQ\"," +
                "      \"e\": \"AQAB\"" +
                "    }]}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        VerificationJwkSelector verificationJwkSelector = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();
        List<JsonWebKey> selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jsonWebKeys = jwks.getJsonWebKeys();
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512);
        jsonWebKeys = jwks.getJsonWebKeys();
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);
        jsonWebKeys = jwks.getJsonWebKeys();
        selected = verificationJwkSelector.selectList(jws, jsonWebKeys);
        assertThat(1, equalTo(selected.size()));
    }


    @Test
    public void someKidSymmetricSelections() throws Exception
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"uno\",  \"k\":\"9gfpc39Jq5H5eR_JbwmAojgUlHIH0GoKz7COz000001\"}," +
                "{\"kty\":\"oct\",\"kid\":\"two\",  \"k\":\"5vlp7BaxRr-a9pOKK7BKNCo88u6cY2o9Lz6-P--_01j\"}," +
                "{\"kty\":\"oct\",\"kid\":\"trois\",\"k\":\"i001cccx6-7rP5p91NeHi3K-jcDjt8N12o3bIeWA081\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);
        List<JsonWebKey> jwks = jsonWebKeySet.getJsonWebKeys();

        VerificationJwkSelector selector = new VerificationJwkSelector();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKeyIdHeaderValue("uno");
        List<JsonWebKey> selectedList = selector.selectList(jws, jwks);
        assertThat(1, equalTo(selectedList.size()));
        JsonWebKey selected = selector.select(jws, jwks);
        assertThat("uno", equalTo(selected.getKeyId()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKeyIdHeaderValue("trois");
        selectedList = selector.selectList(jws, jwks);
        assertThat(1, equalTo(selectedList.size()));
        selected = selector.select(jws, jwks);
        assertThat("trois", equalTo(selected.getKeyId()));
    }

    @Test
    public void selectWithVerifySignatureDisambiguate() throws Exception
    {
        JsonWebSignature jwsWith1stEC = new JsonWebSignature();
        jwsWith1stEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "04tBvYG5QeY8lniGnkZNHMW8b0OPCN6XHuK9g8fsOz8uA_r0Yk-biMkWG7ltOMCFSiiPvEu7jNWfWbk0v-hWOg");

        JsonWebSignature jwsWith2ndEC = new JsonWebSignature();
        jwsWith2ndEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMulM1IvKElmSyK_KBg8afywcxoApA");

        JsonWebSignature jwsWith3rdEC = new JsonWebSignature();
        jwsWith3rdEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "21eYfC_ZNf1FQ1Dtvj4rUiM9jYPgf1zJfeE_b2fclgu36KAN141ICqVjNxQqlK_7Wbct_FDxgyHvej_LEigb2Q");

        JsonWebSignature jwsWith1stRsa = new JsonWebSignature();
        jwsWith1stRsa.setCompactSerialization("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "aECOQefwSdjN1Sj7LWRBV3m1uuHOFDL02nFxMWifACMELrdYZ2i9W_c6Co0SQoJ5HUE0otA8b2mXQBxJ-azetXT4YiJYBpNbKk_H52KOUWvLoOYNwrTKylWjoTprAQpCr9KQWvjn3xrCoers4N63iCC1D9mKOCrUWFzDy-" +
                "-inXDj-5VlLWfCUhu8fjx_lotgUYQVD03Rm06P3OWGz5G_oksJ7VpxDDRAYt7zROgmjFDpSWmAtNEKoAlRTeKnZZSN0R71gznBsofs-jJ8zF0QcFOuAfqHVaDWnKwqS0aduZXm0s7rH61e4OwtQdTtFZqCPldUxlfC7uzvLhxgXrdLew");

        JsonWebSignature jwsWith2ndRSA = new JsonWebSignature();
        jwsWith2ndRSA.setCompactSerialization("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "pgBu9S8g7MC2BN9YNlWD9JhjzWbQVjqpmErW4hMFncKD8bUidIbMBJSI3URXvnMJrLrAC5eB2gb6DccF_txQaqX1X81JbTSdQ44_P1W-1uIIkfIXUvM6OXv48W-CPm8xGuetQ1ayHgU_1ljtdkbdUHZ6irgaeIrFMgZX0J" +
                "db9Eydnfhwvno2oGk3y6ruq2KgKABIdzgvJXfwdOFGn1z0CxwQSVDkFRLsMsBljTwfTd0v3G8OXT8WRMZMGVyAgtKVu3XJyrPNntVqrzdgQQma6S06Y9J9V9t0AlgEAn2B4TqMxYcu1Tjr7bBL_v83zEXhbdcFBYLfJg-LY5wE6rA-dA");


        JsonWebSignature jwsWithUnknownEC = new JsonWebSignature();
        jwsWithUnknownEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTEyNywiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "UE4B0IVPRip-3TDKhNAadCuj_Bf5PlEAn9K94Zd7mP25WNZwxDbQpDElZTZSp-3ngPqQyPGj27emYRHhOnFSAQ");

        JsonWebSignature jwsWith384EC = new JsonWebSignature();
        jwsWith384EC.setCompactSerialization("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTIzMSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "NyRtG_eFmMLQ0XkW5kvdSpzYsm6P5M3U8EBFKIhD-jw8E7FOYw9PZ3_o1PWuLWH3XeArZMW7-bAIVxo2bHqJsSUtB6Tf0NWPtCpUF2c1vbuRXEXkGrCUmc4sKyOBjimC");

        String jwksJson =
                "{\"keys\":[" +
                "{\"kty\":\"EC\",\"x\":\"yd4yK8EJWNY-fyB0veOTNqDt_HqpPa45VTSJjIiI8vM\",\"y\":\"UspqZi9nPaUwBY8kD6MPDHslh5f6UMnAiXsg1l3i6UM\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"x\":\"3WPq7AnMkQekA1ogYFqNS5NBOXPs68xadKvtsn4pgas\",\"y\":\"CEvQFmGwKv96TQYRrgS-nFl9xWfN8PuLnIwBVmtpfp0\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"x\":\"DUYwuVdWtzfd2nkfQ7YEE_3ORRv3o0PYX39qNGVNlyA\",\"y\":\"qxxvewtvj61pnGDS7hWZ026oZehJxtQO3-9oVa6YdT8\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"RSA\",\"n\":\"mGOTvaqxy6AlxHXJFqQc5WSfH3Mjso0nlleF4a1ebSMgnqpmK_s6BSP0v9CyKyn_sBNpsH6dlOsks4qwb88SdvoWpMo2ZCIt8YlefirEaT9J8OQycxMv" +
                        "k7U1t6vCyN8Z68FrwhzzsmnNI_GC723OfMhcEZiRGNRJadPCMPfY3q5PgRrCjUS4v2hQjaicDpZETgbGxWNuNiIPk2CGhG3LJIUX4rx5zrFPQuUKH2Z1zH4E39i3Ab0WBATY0" +
                        "warvlImI5_rT-uCvvepnaQ6Mc4ImpS3anLNjfPlaNVajl5aRuzzRO77XePN-XzFJUVbC_v1-s2IcJf8uB-PMKAtRqz_kw\",\"e\":\"AQAB\"}," +
                "{\"kty\":\"RSA\",\"n\":\"4SoqXJikILVhuwpeOYjbi_KGFXfvMaiBtoDm7nKsVc8ayQ4RBGbQdqHIt6gxSSTHrRSbQ2s5lAHfeyBJ9myQitCwxHFzjIDGcp5_u0wNWJbWUsDnbS-p" +
                        "wAQsZXZ3m6u_aDEC4sCTjOuotzwJniehVAkm2B1OnoYVhooKt9CTjVj1hwMf8Cpr171Vt559LyzUhRml6Se_AJWG_oFLV2c5ALCi2USfq2G_zoXFt9Kc93LJ9XoPy-hbQXA13" +
                        "OXwi9YL_BDLk8nd7QfaUgm77-j6RbOYg0l0PTloggw7km7M1D8iDASfkuII-Dzqedcm3KQb0Quo20HkirlIk67E-jOk6Q\",\"e\":\"AQAB\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);
        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();

        VerificationJwkSelector selector = new VerificationJwkSelector();

        List<JsonWebKey> selected = selector.selectList(jwsWith1stEC, jsonWebKeys);
        assertThat(selected.size(), equalTo(3));

        selected = selector.selectList(jwsWith2ndEC, jsonWebKeys);
        assertThat(selected.size(), equalTo(3));

        selected = selector.selectList(jwsWith3rdEC, jsonWebKeys);
        assertThat(selected.size(), equalTo(3));

        selected = selector.selectList(jwsWithUnknownEC, jsonWebKeys);
        assertThat(selected.size(), equalTo(3));

        selected = selector.selectList(jwsWith384EC, jsonWebKeys);
        assertThat(selected.size(), equalTo(0));

        JsonWebKey chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith1stEC, jsonWebKeys);
        assertThat(chosen.getKey(), equalTo(jwks.getJsonWebKeys().get(0).getKey()));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith2ndEC, jsonWebKeys);
        assertThat(chosen.getKey(), equalTo(jwks.getJsonWebKeys().get(1).getKey()));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith3rdEC, jsonWebKeys);
        assertThat(chosen.getKey(), equalTo(jwks.getJsonWebKeys().get(2).getKey()));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWithUnknownEC, jsonWebKeys);
        assertThat(chosen, is(nullValue()));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith384EC, jsonWebKeys);
        assertThat(chosen, is(nullValue()));

        selected = selector.selectList(jwsWith1stRsa, jsonWebKeys);
        assertThat(selected.size(), equalTo(2));

        selected = selector.selectList(jwsWith2ndRSA, jsonWebKeys);
        assertThat(selected.size(), equalTo(2));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith1stRsa, jsonWebKeys);
        assertThat(chosen.getKey(), equalTo(jwks.getJsonWebKeys().get(3).getKey()));

        chosen = selector.selectWithVerifySignatureDisambiguate(jwsWith2ndRSA, jsonWebKeys);
        assertThat(chosen.getKey(), equalTo(jwks.getJsonWebKeys().get(4).getKey()));
    }

    @Test
    public void selectWithVerifySignatureDisambiguateDifferentRsaSizes1() throws Exception
    {
        PublicJsonWebKey rsaJwk2048 = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"RSA\",\"n\":\"s3xFORqMy1xG-9Xx0i2y2rXxtoBCpMPeZd4F4do8RWdGRKJQ7Vrj5dtgym0xZoV70SR92d3h0ofLAGTswk6t0IxtO0Y5UHN_mOkdxXTJpYLiVzR-1xIttOhVlHjXnZzb_cCXoXoNRnY8RqVPDN386Wpx4f60MpHYHsrKn-r4LY7LHH8Bt70t1KGIQNU9fPdlClItlpKPSWmiGAhh6P6aJi8SVkx5wLtz0Y95R7jqb6EPRXTKCYD-yWMWik1p-st2wo4B7LyLw_wCRkimAX2jssswGL9Rpc5MYaA5TPaQmJjruT1IEv50-g8f7pxioDz7tNAfbggyDYUPZDm-EFcdhw\",\"e\":\"AQAB\",\"d\":\"Q4qiKgj5rpU9CQvLgkI8Kd2J5hmB-qrSiBbys7kCMUPZx34lYgxv8lGJrONGUcQtgdhvm4rJrgX3uGBCUCR3eCFAAaw9aS7td0dSMrnuH-CO-C4DBUAL_yXm_oYy7VbX2jedV-CsGjXoHNWcV8U5pUSvMlI80ULcx0mc0m0Dk3ClOSTVuodV8WBsad9RqhcLPUS8oMH-Iqb2l5u7bxarIiVAY3f75LNw9F194XtUKl7j5kBi3S4Qp39zmxu_NUK_sSWP1pWXuMxYHJ1cnvbemgIL5zzMmKSpoNzgrAtmC-9ReDWW9ZoGt5OruwLgGpGdDov4y62vel-bUcKT3vMOwQ\",\"p\":\"35rWLZ9j8bcEbSCNdHguSmMHyIL31xIVspPVmZE2vrswYssx3DyF2oF6miXz4cwd_TnUo0wbN2tIM8kUY-zc2LPVqHzxJbF4GMf3cpYRSbYW0r9vV0jjjZQXNer7_HCQNZC1pWxRA7817UQMn3reCRKVhKUzzdYvim0INeYppTc\",\"q\":\"zX0cv0ILtaQuPv9bU2phiTi9fj5oDeOGvq5sF46hHYhDcIb3_ju9oF-bG45gg6DNWXNH3YV6umA-BasejO0W0ir7r9IE7GPQPVtMpDWDVo1w-fRDS4BiSFOaOojHoY3POz087SDIGIC5kNmz6nOkQDb38urPVamMT1461iWUcjE\",\"dp\":\"qYUEfSAKsFTVCTqVo0f9qC192BjadnXidzk2xa7etyjI3Q05ZsOHowlofnbpdzS9Q55VQ9vOAmzWF1SJndwT7kIgaBUY6T-rUfY_9eIphx2CHhI-AgljYpF0K09T7KUV31YvMBN3NAUBiDh_7WRD8tLhAegQ5ytLbYGNqPcueW8\",\"dq\":\"EmLnd5WJRq9yE-D1YvlZ0NVq3yjmVpfNLrKcqV7xu5q9rgvllLHzva3QSx7qM9znguF1xLR0zshdxFQTX7i3GgcOjiTUm_IyZ8sLiIXhQpVVTog0nUTXhnE0k5g5hJMTv9Ey6mTMgqTB9dwE5S2DvNsuRGYONzP8gf2EdjTWm4E\",\"qi\":\"YMui-he-fz_wv-ZdV--r6j4Utdz9p4BtjtfEA1_XQ40U944EIBpuZToKgE9Fquqqz6E3oc_2cgr3NBEXMz2hdUgkM6s4jz-Mtc2PZRSVRQZq7RTnCBaahHr9mQhaEanoae69M79SvkcTGK_APnodFrfWZJfEUPffK0izKMM5KTs\"}");
        PublicJsonWebKey rsaJwk4096 = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"RSA\",\"n\":\"oOtx-ZO3KSNr_Wy5VJjXUJOuZq70nyd4QWTXsM4bQGqZlGPtMAqjxo-Qkw6WGubJxABtDxKUJBlmNgqieEFrFixV-_-DaujvoaXYi4C1T5a7WdIIYyEZmTztoeVnyWusYJBRpjONu4uMIfT-flbkmQu9MFs_0FEApLrhiMkujXxOffmw8gBVE2dmSwU74IpC8VsaZBInjr6B0-LLCYuFaRHfF5Nnq2wV3Roo8m_rhH-yrnEf9fbaoZH6rPTrBWc_thJq-X7qeFmHAyELCM_xlGSwnz2H8jPTRWJU4feTS7Ons71Ig0ot7NJF4GBHJ4HyeBjj3a2LQUA14kiDfDAkJntS3egVAIw4No7We-pr5JdOPIZztwriZ2w_8aUDhqBNgXHuYAekQLj0qjRcwFoENy5pD-FsIXUeDO7agNbpbl-Wlgos2M97eaut359HPmZ7veLj0zhK3Uy6nsT0SO7-JhrqEnALn-AxXhU0yN3AntwU_qhjrtgrxcSYVYGN5os1xvbBoKmtlQik_vWO5JoiRXpz2EtT9EUQcdY16M1eTjStOnlk9BcFSvbNsHj_skEAtP_iCAdlQkkKYqzhCZSK1QCAp20_F2hlMlx-MS1dWgZjjf5MDebsTlu7c6IXxhAbM42m5EUQdpPp8dv0ValaaCU_gL7_G0-gXlqM-Yl23K0\",\"e\":\"AQAB\",\"d\":\"EmxCJS-bJZOPlnjvEtdYtznhGpJnIR10sA_qfaxrBEnwAUQbcIeXTnE7PQrLdpL7gHwIAFTBLwzVXdSD2z6qEuTKh0oucnvui1QgYYA_wbfhBRx9p1OvyZJnJkTMSAwStQ9wuZVnYZRNW8nfpPkvvLHSXAnmWWQcrb9TeMSHlt0nY1bFwj71fn41ANu9iixqE5W5hMFrU_VNicOKOTKG-It6Pgm7Ma3zJtgK3g6gKRAxlbUP0qoLR7odt9VmXrz-V0ruglfcYiDlyx7qU3zzDGkmq2Rw_vKd-nCShThB3cXYqkQ-XAGPFnDQXSrImqZO6x72X3ex3KuMP7bLjtk4Ghx3yFxRUNJAaQEKgMTvFNsybx7oCPTOXxAVhxCeEuv1o1b4g6mCs9XVlUPVnZwt4fW-QHeenqeLe-Y3gsPEAkGdsZoEL0eQqjwVad-MdA0r3BHJQRjBp2YDujF5V8ypJeR6CE1ILlc2W4DvhzgpGF3m2RUUqSXVj1aOCciZGAwtU-Lhgg4hDkv8ZV6nKE-O2FbI_126n41e-PeBoh8214RAJeAW82y3AAP3lwd38EfLIxt17rQ2bKIDx4kJmgtW5a4LiAshvYN3SgqtyKvJSbDllLIy6OdXWlSv_ogcbeDnY3F5MNBfn6moGupsvOWkOH3zX6TxifBDjsebwMab8UE\",\"p\":\"9FQGthSnO6TSEFODI-NjyyqdWwWGDHueIjAKBB76hnc5XAojVJepmbnD3HrUm3ujqbA9uGygdTl88gHiv-nDxYkRL9foNmTdCrzIqqxZnYfmHQjCbRXbc8oFd-bDRNLMZFX7TJbnaSugdgDNcVLTH8nd-qKH4VLdGnrTiQrq4FjEEDSdgwfzDbM9LrNxT_9KZlCsEj9eTqGJW5fugU2QvfVvdocnRKwMkg22rQ8Rt2IDexD3LSLcZwjF3yd1Bxm0VA1ks-Gc229NSyETGf45eNn9M6Uxb_jXM7hpdxAQyVh8Ua_bMzh6u5EDgiymigwgQx79eJswyzSeYmD99VwmHQ\",\"q\":\"qJtjOBXxIMQkD5I60PqbQ8l3ehIs3uXaOzMt8beyEzLfSH77fu-cZGkYLYtGnKuCkt_Yv-gN6IQgBF9kE7Jic5FIITSnC2Qjem7BAmDV6-2f9xRSisNznR-tScsMMtIKVFm4Gr0rZpZICRNKSOZJ4EhL17JEqmUihw--9H1djC1K9Emgy9nJhgbUrWuJ_ShF2PZeUet_ABI6P11m3wUmCZScf3o4prqqJQcdjVTYXdSA6XfnzTilIDFCSlNJY4uAYZ5ZzOxQ2W3x1GXXFldmWv8wplylumWbY9jCCRUVWJiZqD0-cqBVVNuofVg0Po4usndlNGcpVp2HbWxJBJKL0Q\",\"dp\":\"XGDkxLVcYZ242vlobQpNsgRjyIV3IIMg0BZPwy0fVfYAFv-ySgqp0ni9SECc4EjIIaGERJW1uXzJ9AqofB1bqvVfLTK6Fs7eEHA-guF1ZK18YN_t-ya3ebkZhjMXA4-cPheQU23_AvG-0r8M7lr9flhp-Ji5PYWCGb_0-SzKj5agUuxB3cgEqtppOJ4aKsAAllzMIn4ZHyvObnYsdHEqV9hTk4IYY8uVWSecOSSocyi43jAU9NjocoCLqAsYIV4jo2AJAkY8c29KzywrN7m6ayoopP1Biu-QFnsUTTMi1a4CGzSdcWlaZk62_-H3-dwJ2rb96TrsIPi9Jb88Zie4NQ\",\"dq\":\"dfX4zbV0NONlA0vgQHMEi8F5CHuMzwlqy_47h6BoQsxVsOe-VomXFhz84GhPp67KtK1NfL4CdQlzSPvgDXPBM2-SUkD_GZYeyDqSaHKNV_mw7_FU6mZiDayq1TTsvOV8epUmm_Z7VdOQZGENmMEdMIAEJ80-AySsqmeWxoCrITZS-WRFzjj5p_5Bb28MZIR3kZqUVKX4_XjDLa_QF_oHKa7CauF8nxF7llpLD6Url0HkSvMrxsV5qXMtGMj6UF26HRHna9ptmiE0jtANUkEliEZ_p_SrsiQCOjHdVvNcMtbYsf7fIN0RtkPTtpYuPxHEk_G6aZY_Mq0VobWfxEYu8Q\",\"qi\":\"fZKGdPoeWTVRR5sbkP7eh_Kv8kYK4FDmHqwyt4e6Wgb-Sdnn2ZhMI-4YzVMtSer167crPXBkuDbCCdXr2yBMT4XsyjFzKqr7ZqU-vQjRgYD7lDJtWF5KLLmxt8loM3tO0Ei1dg1dr8Vlc4U8JzIjpRmQxLqSkqU9cpIPXcTzjOH8SYWi9IZhTLanwpUEYczfb2h0wkEVNY2zZrONkF7aj-fjkVxpkuDVDx3m6Kc7-5JgX7Kt4p7t-JLiym-yabf1yEeU3DGS690Xf65XBQZKRUr4omMPPXm9_aTop7mtlZATqop7jeqeGSRuwaoilBZtJoidLxi2F2eUWVhASZg2Vg\"}");

        // signed w/ the 4096 one
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization("eyJhbGciOiJSUzUxMiJ9.eyJjbGFpbSI6InZhbHVlIn0.gVe8O1YzNdOlJmcy6s5i6E1TH9oMNQqNsYYoRjgPDNLK-daApzH2fkS7D1VWaBJc50sETNiy6VRzj_ZGTIxJYFRi1HqaQuos62VF1_DdLx2PbGSMoD2Orw6sBuBK179jNYOQ8RBwEfbVmsHAQATZtc5hRxFmpfcJ_Ml3_ELoPRj-LNF5eygPaHRaVWm-Gjy1mwm7LQ4vinoWB2OhHnO9if-muYEJFLMzfZDAuq4EKnsze5XWuwrh8c0eDmJzt_KJek1cTFfWsROydyohBNJWXTtP87Ee3jFw72V0i22zWc0AHo3ydr5F-g0QW7JoNfJwTd6Wr2lqTP-WVTQklawqM2uZ6E6uElWcokFwYBFvUa1FMvD1bYQQLXklFGRJ33yGOwozz2L6-QATVjyyN_4oHmFUMwjSWjPQVJvqHZOB5vH6w7dc9CKtMgBCh4SNJMW3pmY1bzoTDEUuOOgrGiPdipG5si7HgPwB3DrcE3ZUeYXeNaVjoOOCzfLwRzQG2hdrsH5He16RuB-EcGzk4tebwiHETJsWwW2PGY5DVRYAF80IvjUkF1L4iwKGNwAnO5t3BCHSrxJxGrNWoH--puEMTystNOmKtcgpp8XrmMA3Wd92_aNiIXioj82VAkBkuUBoDMskyedR9V0HqVuBc8EIpvvQHgqz3LiIJdHRsZKj0Ts");

        VerificationJwkSelector selector = new VerificationJwkSelector();
        JsonWebKey chosen = selector.selectWithVerifySignatureDisambiguate(jws, Arrays.<JsonWebKey>asList(rsaJwk2048, rsaJwk4096));
        assertThat(chosen.getKey(), equalTo(rsaJwk4096.getKey()));
    }

    @Test
    public void selectWithVerifySignatureDisambiguateDifferentRsaSizes2() throws Exception
    {
        PublicJsonWebKey rsaJwk2048 = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"RSA\",\"n\":\"s3xFORqMy1xG-9Xx0i2y2rXxtoBCpMPeZd4F4do8RWdGRKJQ7Vrj5dtgym0xZoV70SR92d3h0ofLAGTswk6t0IxtO0Y5UHN_mOkdxXTJpYLiVzR-1xIttOhVlHjXnZzb_cCXoXoNRnY8RqVPDN386Wpx4f60MpHYHsrKn-r4LY7LHH8Bt70t1KGIQNU9fPdlClItlpKPSWmiGAhh6P6aJi8SVkx5wLtz0Y95R7jqb6EPRXTKCYD-yWMWik1p-st2wo4B7LyLw_wCRkimAX2jssswGL9Rpc5MYaA5TPaQmJjruT1IEv50-g8f7pxioDz7tNAfbggyDYUPZDm-EFcdhw\",\"e\":\"AQAB\",\"d\":\"Q4qiKgj5rpU9CQvLgkI8Kd2J5hmB-qrSiBbys7kCMUPZx34lYgxv8lGJrONGUcQtgdhvm4rJrgX3uGBCUCR3eCFAAaw9aS7td0dSMrnuH-CO-C4DBUAL_yXm_oYy7VbX2jedV-CsGjXoHNWcV8U5pUSvMlI80ULcx0mc0m0Dk3ClOSTVuodV8WBsad9RqhcLPUS8oMH-Iqb2l5u7bxarIiVAY3f75LNw9F194XtUKl7j5kBi3S4Qp39zmxu_NUK_sSWP1pWXuMxYHJ1cnvbemgIL5zzMmKSpoNzgrAtmC-9ReDWW9ZoGt5OruwLgGpGdDov4y62vel-bUcKT3vMOwQ\",\"p\":\"35rWLZ9j8bcEbSCNdHguSmMHyIL31xIVspPVmZE2vrswYssx3DyF2oF6miXz4cwd_TnUo0wbN2tIM8kUY-zc2LPVqHzxJbF4GMf3cpYRSbYW0r9vV0jjjZQXNer7_HCQNZC1pWxRA7817UQMn3reCRKVhKUzzdYvim0INeYppTc\",\"q\":\"zX0cv0ILtaQuPv9bU2phiTi9fj5oDeOGvq5sF46hHYhDcIb3_ju9oF-bG45gg6DNWXNH3YV6umA-BasejO0W0ir7r9IE7GPQPVtMpDWDVo1w-fRDS4BiSFOaOojHoY3POz087SDIGIC5kNmz6nOkQDb38urPVamMT1461iWUcjE\",\"dp\":\"qYUEfSAKsFTVCTqVo0f9qC192BjadnXidzk2xa7etyjI3Q05ZsOHowlofnbpdzS9Q55VQ9vOAmzWF1SJndwT7kIgaBUY6T-rUfY_9eIphx2CHhI-AgljYpF0K09T7KUV31YvMBN3NAUBiDh_7WRD8tLhAegQ5ytLbYGNqPcueW8\",\"dq\":\"EmLnd5WJRq9yE-D1YvlZ0NVq3yjmVpfNLrKcqV7xu5q9rgvllLHzva3QSx7qM9znguF1xLR0zshdxFQTX7i3GgcOjiTUm_IyZ8sLiIXhQpVVTog0nUTXhnE0k5g5hJMTv9Ey6mTMgqTB9dwE5S2DvNsuRGYONzP8gf2EdjTWm4E\",\"qi\":\"YMui-he-fz_wv-ZdV--r6j4Utdz9p4BtjtfEA1_XQ40U944EIBpuZToKgE9Fquqqz6E3oc_2cgr3NBEXMz2hdUgkM6s4jz-Mtc2PZRSVRQZq7RTnCBaahHr9mQhaEanoae69M79SvkcTGK_APnodFrfWZJfEUPffK0izKMM5KTs\"}");
        PublicJsonWebKey rsaJwk4096 = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"RSA\",\"n\":\"oOtx-ZO3KSNr_Wy5VJjXUJOuZq70nyd4QWTXsM4bQGqZlGPtMAqjxo-Qkw6WGubJxABtDxKUJBlmNgqieEFrFixV-_-DaujvoaXYi4C1T5a7WdIIYyEZmTztoeVnyWusYJBRpjONu4uMIfT-flbkmQu9MFs_0FEApLrhiMkujXxOffmw8gBVE2dmSwU74IpC8VsaZBInjr6B0-LLCYuFaRHfF5Nnq2wV3Roo8m_rhH-yrnEf9fbaoZH6rPTrBWc_thJq-X7qeFmHAyELCM_xlGSwnz2H8jPTRWJU4feTS7Ons71Ig0ot7NJF4GBHJ4HyeBjj3a2LQUA14kiDfDAkJntS3egVAIw4No7We-pr5JdOPIZztwriZ2w_8aUDhqBNgXHuYAekQLj0qjRcwFoENy5pD-FsIXUeDO7agNbpbl-Wlgos2M97eaut359HPmZ7veLj0zhK3Uy6nsT0SO7-JhrqEnALn-AxXhU0yN3AntwU_qhjrtgrxcSYVYGN5os1xvbBoKmtlQik_vWO5JoiRXpz2EtT9EUQcdY16M1eTjStOnlk9BcFSvbNsHj_skEAtP_iCAdlQkkKYqzhCZSK1QCAp20_F2hlMlx-MS1dWgZjjf5MDebsTlu7c6IXxhAbM42m5EUQdpPp8dv0ValaaCU_gL7_G0-gXlqM-Yl23K0\",\"e\":\"AQAB\",\"d\":\"EmxCJS-bJZOPlnjvEtdYtznhGpJnIR10sA_qfaxrBEnwAUQbcIeXTnE7PQrLdpL7gHwIAFTBLwzVXdSD2z6qEuTKh0oucnvui1QgYYA_wbfhBRx9p1OvyZJnJkTMSAwStQ9wuZVnYZRNW8nfpPkvvLHSXAnmWWQcrb9TeMSHlt0nY1bFwj71fn41ANu9iixqE5W5hMFrU_VNicOKOTKG-It6Pgm7Ma3zJtgK3g6gKRAxlbUP0qoLR7odt9VmXrz-V0ruglfcYiDlyx7qU3zzDGkmq2Rw_vKd-nCShThB3cXYqkQ-XAGPFnDQXSrImqZO6x72X3ex3KuMP7bLjtk4Ghx3yFxRUNJAaQEKgMTvFNsybx7oCPTOXxAVhxCeEuv1o1b4g6mCs9XVlUPVnZwt4fW-QHeenqeLe-Y3gsPEAkGdsZoEL0eQqjwVad-MdA0r3BHJQRjBp2YDujF5V8ypJeR6CE1ILlc2W4DvhzgpGF3m2RUUqSXVj1aOCciZGAwtU-Lhgg4hDkv8ZV6nKE-O2FbI_126n41e-PeBoh8214RAJeAW82y3AAP3lwd38EfLIxt17rQ2bKIDx4kJmgtW5a4LiAshvYN3SgqtyKvJSbDllLIy6OdXWlSv_ogcbeDnY3F5MNBfn6moGupsvOWkOH3zX6TxifBDjsebwMab8UE\",\"p\":\"9FQGthSnO6TSEFODI-NjyyqdWwWGDHueIjAKBB76hnc5XAojVJepmbnD3HrUm3ujqbA9uGygdTl88gHiv-nDxYkRL9foNmTdCrzIqqxZnYfmHQjCbRXbc8oFd-bDRNLMZFX7TJbnaSugdgDNcVLTH8nd-qKH4VLdGnrTiQrq4FjEEDSdgwfzDbM9LrNxT_9KZlCsEj9eTqGJW5fugU2QvfVvdocnRKwMkg22rQ8Rt2IDexD3LSLcZwjF3yd1Bxm0VA1ks-Gc229NSyETGf45eNn9M6Uxb_jXM7hpdxAQyVh8Ua_bMzh6u5EDgiymigwgQx79eJswyzSeYmD99VwmHQ\",\"q\":\"qJtjOBXxIMQkD5I60PqbQ8l3ehIs3uXaOzMt8beyEzLfSH77fu-cZGkYLYtGnKuCkt_Yv-gN6IQgBF9kE7Jic5FIITSnC2Qjem7BAmDV6-2f9xRSisNznR-tScsMMtIKVFm4Gr0rZpZICRNKSOZJ4EhL17JEqmUihw--9H1djC1K9Emgy9nJhgbUrWuJ_ShF2PZeUet_ABI6P11m3wUmCZScf3o4prqqJQcdjVTYXdSA6XfnzTilIDFCSlNJY4uAYZ5ZzOxQ2W3x1GXXFldmWv8wplylumWbY9jCCRUVWJiZqD0-cqBVVNuofVg0Po4usndlNGcpVp2HbWxJBJKL0Q\",\"dp\":\"XGDkxLVcYZ242vlobQpNsgRjyIV3IIMg0BZPwy0fVfYAFv-ySgqp0ni9SECc4EjIIaGERJW1uXzJ9AqofB1bqvVfLTK6Fs7eEHA-guF1ZK18YN_t-ya3ebkZhjMXA4-cPheQU23_AvG-0r8M7lr9flhp-Ji5PYWCGb_0-SzKj5agUuxB3cgEqtppOJ4aKsAAllzMIn4ZHyvObnYsdHEqV9hTk4IYY8uVWSecOSSocyi43jAU9NjocoCLqAsYIV4jo2AJAkY8c29KzywrN7m6ayoopP1Biu-QFnsUTTMi1a4CGzSdcWlaZk62_-H3-dwJ2rb96TrsIPi9Jb88Zie4NQ\",\"dq\":\"dfX4zbV0NONlA0vgQHMEi8F5CHuMzwlqy_47h6BoQsxVsOe-VomXFhz84GhPp67KtK1NfL4CdQlzSPvgDXPBM2-SUkD_GZYeyDqSaHKNV_mw7_FU6mZiDayq1TTsvOV8epUmm_Z7VdOQZGENmMEdMIAEJ80-AySsqmeWxoCrITZS-WRFzjj5p_5Bb28MZIR3kZqUVKX4_XjDLa_QF_oHKa7CauF8nxF7llpLD6Url0HkSvMrxsV5qXMtGMj6UF26HRHna9ptmiE0jtANUkEliEZ_p_SrsiQCOjHdVvNcMtbYsf7fIN0RtkPTtpYuPxHEk_G6aZY_Mq0VobWfxEYu8Q\",\"qi\":\"fZKGdPoeWTVRR5sbkP7eh_Kv8kYK4FDmHqwyt4e6Wgb-Sdnn2ZhMI-4YzVMtSer167crPXBkuDbCCdXr2yBMT4XsyjFzKqr7ZqU-vQjRgYD7lDJtWF5KLLmxt8loM3tO0Ei1dg1dr8Vlc4U8JzIjpRmQxLqSkqU9cpIPXcTzjOH8SYWi9IZhTLanwpUEYczfb2h0wkEVNY2zZrONkF7aj-fjkVxpkuDVDx3m6Kc7-5JgX7Kt4p7t-JLiym-yabf1yEeU3DGS690Xf65XBQZKRUr4omMPPXm9_aTop7mtlZATqop7jeqeGSRuwaoilBZtJoidLxi2F2eUWVhASZg2Vg\"}");

        // signed w/ the 2048 one
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization("eyJhbGciOiJSUzUxMiJ9.eyJjbGFpbSI6InZhbHVlIn0.Wp5B7mYIK-Pwx-3BQJvy8M6lOoUS1kofMSC-eSWtY44NUwizjAmjwnLWPbdBgSFDdTtqRE8NQdFn6aHLURdtCR4LRSgJVkdE9M_ggbvLfB2nZ6CFGbg89AWZ2Uq-EQPIzXrg9QiK9OeZjQyFgp1i89Eucy0Xc5bTYRCzLxfEbHWzFhacPFXm2RuZMSYbYJK2-6yDnfQGsyH6B50toCZSJI0e4SKF71U9EU78Y7PLTwyMcQLbgTsxkv0o0AKyZYujWM_GqKx_m2qbfAioqrNBg1-XuGnmv5hxmqFTMFCYBeOXeltuaVcC9iRxIZOKBDxjdENO_pmomgMrdD730tz43Q");

        VerificationJwkSelector selector = new VerificationJwkSelector();

        JsonWebKey chosen = selector.selectWithVerifySignatureDisambiguate(jws, Arrays.<JsonWebKey>asList(rsaJwk4096, rsaJwk2048));
        assertThat(chosen.getKey(), equalTo(rsaJwk2048.getKey()));
    }


    @Test
    public void keyOpsInSelectorKindaRandom() throws Exception
    {
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"EC\",\"key_ops\":[\"verify\",\"nope\",\"whatever\"],\"x\":\"H78v6ZjjJPKmtrQNRECVQiGXFKOYFMHLG0q7SJd__5s\",\"y\":\"7-U3zo9sDyg7BCOoY3Yj_SSZdXuiTJnG1YvjTtqsrfs\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"S0ebOlceQ60hWjm1-Kuj5P3xH1t_NCSMfumBG1ULM5M\",\"y\":\"l3dzIN8mJofWUtQT3jHf-c2jRViXcWam4tfsiyUp6RI\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"key_ops\":[\"deriveBits\",\"unknown\"],\"x\":\"1O1K45F2hApgHgF6M1HCh7352uojDnXxcmiYdJuNBSo\",\"y\":\"MoIl5LLxXIMPfBSUPJXKO8hyv6lCsHgmyc2GWeqi77I\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"uHo8tp88587_RB07P3U2Ev7EZCqhpplFXfrOLyqnVwE\",\"y\":\"y9iW7nGBH_UkuRkn8YuQP8Lc5ftCqkzWDkxzBrof6PU\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"vt4xF93UAJ733TuKEFN0RymIo5fW_iluEGL5s5cq098\",\"y\":\"AUbaLliBS6XE28Dx_sOO4M_Xc4rJH35ytrw_SRKZhRw\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"x\":\"JgKilKl8qjJ9-3Fnr_l282-Z9N_hxBg54TGs_Gqn9yg\",\"y\":\"wVZH4ova35tsViVLmPY8NbZPnditgKO4JcD2zT6ePpg\",\"crv\":\"P-256\"}]}");

        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();

        VerificationJwkSelector selector = new VerificationJwkSelector();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        List<JsonWebKey> selected = selector.selectList(jws, jsonWebKeys);
        assertThat(selected.size(), equalTo(4));
    }

    @Test
    public void keyOpsInSelector() throws Exception
    {
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"EC\",\"key_ops\":[\"encrypt\"],\"x\":\"eBTzLIja4bP6Q25Ns5NBfb1PGuT5qVqxtzhK0gmA2wY\",\"y\":\"ToPEAa1KCYkqZ9z0tOt3vzI8vbWXSBVPIau3h68-I9E\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"key_ops\":[\"encrypt\"],\"x\":\"lziTuxjaY7mq4UcPocqLGGxDlz9NWKSmNWbFPQM1JW8KJdlgw7s0t4xbjVBuPh-h\",\"y\":\"bmwU8zrsuM88wIGUod6DgBg-yP0aEdXpbB00cRVpCI1Wd8BnSShz0DNGnu5pl4qN\",\"crv\":\"P-384\"}," +
                "{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"tZXiftlYcS8qfJvB0ZL7D2QnL2TX5FHwtVzYUn40ZMlqXp-jxb7SowVTrevWTWP-\",\"y\":\"tJG_JYi8dVIa8pusu77OuiW1HXzB-s-q2uf55XXBRu10A2v8xOIO_80ZI7YtPPb4\",\"crv\":\"P-384\"}," +
                "{\"kty\":\"EC\",\"key_ops\":[\"verify\"],\"x\":\"gfcWFvzU0CrtEImwdjJTgoYKpwcFO5EIykj1Wx8wx_M\",\"y\":\"9ilsfMCVn_FRyy1p20mZRyBuSTHnU1fss_TlbY8qo40\",\"crv\":\"P-256\"}]}\n");

        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();

        VerificationJwkSelector selector = new VerificationJwkSelector();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        List<JsonWebKey> selected = selector.selectList(jws, jsonWebKeys);
        assertThat(selected.size(), equalTo(1));
        assertThat(selected.get(0).getKey(), equalTo(jsonWebKeys.get(3).getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);

        selected = selector.selectList(jws, jsonWebKeys);
        assertThat(selected.size(), equalTo(1));
        assertThat(selected.get(0).getKey(), equalTo(jsonWebKeys.get(2).getKey()));
    }

    @Test
    public void useInSelector() throws Exception
    {
        JsonWebKeySet jwks = new JsonWebKeySet("{\"keys\":[" +
                "{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"eBTzLIja4bP6Q25Ns5NBfb1PGuT5qVqxtzhK0gmA2wY\",\"y\":\"ToPEAa1KCYkqZ9z0tOt3vzI8vbWXSBVPIau3h68-I9E\",\"crv\":\"P-256\"}," +
                "{\"kty\":\"EC\",\"use\":\"enc\",\"x\":\"lziTuxjaY7mq4UcPocqLGGxDlz9NWKSmNWbFPQM1JW8KJdlgw7s0t4xbjVBuPh-h\",\"y\":\"bmwU8zrsuM88wIGUod6DgBg-yP0aEdXpbB00cRVpCI1Wd8BnSShz0DNGnu5pl4qN\",\"crv\":\"P-384\"}," +
                "{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"tZXiftlYcS8qfJvB0ZL7D2QnL2TX5FHwtVzYUn40ZMlqXp-jxb7SowVTrevWTWP-\",\"y\":\"tJG_JYi8dVIa8pusu77OuiW1HXzB-s-q2uf55XXBRu10A2v8xOIO_80ZI7YtPPb4\",\"crv\":\"P-384\"}," +
                "{\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"gfcWFvzU0CrtEImwdjJTgoYKpwcFO5EIykj1Wx8wx_M\",\"y\":\"9ilsfMCVn_FRyy1p20mZRyBuSTHnU1fss_TlbY8qo40\",\"crv\":\"P-256\"}]}\n");

        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();

        VerificationJwkSelector selector = new VerificationJwkSelector();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        List<JsonWebKey> selected = selector.selectList(jws, jsonWebKeys);
        assertThat(selected.size(), equalTo(1));
        assertThat(selected.get(0).getKey(), equalTo(jsonWebKeys.get(3).getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384);

        selected = selector.selectList(jws, jsonWebKeys);
        assertThat(selected.size(), equalTo(1));
        assertThat(selected.get(0).getKey(), equalTo(jsonWebKeys.get(2).getKey()));
    }
}
