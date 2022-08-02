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

package org.jose4j.jwk;

import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.junit.Test;

import java.security.MessageDigest;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.jose4j.lang.HashUtil.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class Rfc7638JwkThumbprintTest
{
    @Test
    public void testRsaFromRfcExample3_1() throws JoseException
    {
        // http://tools.ietf.org/html/rfc7638#section-3.1
        String json = "     {\n" +
                "      \"kty\": \"RSA\",\n" +
                "      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\n" +
                "            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\n" +
                "            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\n" +
                "            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\n" +
                "            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\n" +
                "            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "      \"e\": \"AQAB\",\n" +
                "      \"alg\": \"RS256\",\n" +
                "      \"kid\": \"2011-04-29\"\n" +
                "     }";

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(json);
        String actual = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        String calculated = jsonWebKey.calculateBase64urlEncodedThumbprint(SHA_256);
        assertThat(actual, equalTo(calculated));
    }

    @Test
    public void testOct() throws JoseException
    {
        String json = "{\"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\",\"kty\":\"oct\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        byte[] thumb = jwk.calculateThumbprint(SHA_256);

        MessageDigest messageDigest = getMessageDigest(SHA_256);
        byte[] digest = messageDigest.digest(StringUtil.getBytesUtf8(json));

        assertArrayEquals(digest, thumb);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\", \"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}");

        assertThat(jwk.calculateBase64urlEncodedThumbprint(SHA_256), equalTo(jsonWebKey.calculateBase64urlEncodedThumbprint(SHA_256)));
    }

    @Test
    public void testEc() throws JoseException
    {
        String json = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
                "\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
                "\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"}";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        byte[] thumb = jwk.calculateThumbprint(SHA_256);

        MessageDigest messageDigest = getMessageDigest(SHA_256);
        byte[] digest = messageDigest.digest(StringUtil.getBytesUtf8(json));

        assertArrayEquals(digest, thumb);


        json = "{\"kty\":\"EC\"," +
                "\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
                "\"crv\":\"P-256\"," +
                "\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"}";

        jwk = JsonWebKey.Factory.newJwk(json);
        thumb = jwk.calculateThumbprint(SHA_256);

        assertArrayEquals(digest, thumb);
    }

    @Test
    public void testEcFromNimb() throws JoseException
    {
        String json = "{\"crv\":\"P-256\"," +
                " \"kty\":\"EC\"," +
                " \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                " \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        String thumb = jwk.calculateBase64urlEncodedThumbprint(SHA_256);
        assertThat("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s", equalTo(thumb));
    }

    @Test
    public void testOctFromNimb() throws JoseException
    {
        String json = "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        String thumb = jwk.calculateBase64urlEncodedThumbprint(SHA_256);
        assertThat("k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc", equalTo(thumb));
    }

    @Test
    public void joseWgListTestVectors() throws Exception
    {
        // https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
        // ... https://mailarchive.ietf.org/arch/msg/jose/nxct2sTGJvHxtOtofmUA8bMe6B0
        JsonWebKey jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\", \"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}");
        String thumb = "7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g";
        assertThat(thumb, equalTo(jwk.calculateBase64urlEncodedThumbprint(SHA_256)));

        jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"EC\",\n" +
                " \"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\",\n" +
                " \"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\",\n" +
                " \"crv\":\"P-256\"}");
        thumb = "j4UYwo9wrtllSHaoLDJNh7MhVCL8t0t8cGPPzChpYDs";
        assertThat(thumb, equalTo(jwk.calculateBase64urlEncodedThumbprint(SHA_256)));

        jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"EC\",\n" +
                " \"x\":\"Aeq3uMrb3iCQEt0PzSeZMmrmYhsKP5DM1oMP6LQzTFQY9-F3Ab45xiK4AJxltXEI-87g3gRwId88hTyHgq180JDt\",\n" +
                " \"y\":\"ARA0lIlrZMEzaXyXE4hjEkc50y_JON3qL7HSae9VuWpOv_2kit8p3pyJBiRb468_U5ztLT7FvDvtimyS42trhDTu\",\n" +
                " \"crv\":\"P-521\"}");
        thumb = "rz4Ohmpxg-UOWIWqWKHlOe0bHSjNUFlHW5vwG_M7qYg";
        assertThat(thumb, equalTo(jwk.calculateBase64urlEncodedThumbprint(SHA_256)));

        jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"EC\",\n" +
                " \"x\":\"2jCG5DmKUql9YPn7F2C-0ljWEbj8O8-vn5Ih1k7Wzb-y3NpBLiG1BiRa392b1kcQ\",\n" +
                " \"y\":\"7Ragi9rT-5tSzaMbJlH_EIJl6rNFfj4V4RyFM5U2z4j1hesX5JXa8dWOsE-5wPIl\",\n" +
                " \"crv\":\"P-384\"}");
        thumb = "vZtaWIw-zw95JNzzURg1YB7mWNLlm44YZDZzhrPNetM";
        assertThat(thumb, equalTo(jwk.calculateBase64urlEncodedThumbprint(SHA_256)));

        jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"NGbwp1rC4n85A1SaNxoHow\"}");
        thumb = "5_qb56G0OJDw-lb5mkDaWS4MwuY0fatkn9LkNqUHqMk";
        assertThat(thumb, equalTo(jwk.calculateBase64urlEncodedThumbprint(SHA_256)));
    }


    @Test
    public void kidDerivationUsingJwkThumbCompare() throws Exception
    {
        // kid values from an external source that were derived using 7638 JWK thumbprint
        // this test is just to confirm that we get the same value when calculating the 7638 JWK thumbprint
        // (they seem to have also confused the x5t stuff but that's superfluous to this check)

        String jwksJson = "{\"keys\": [{\"e\": \"AQAB\", " +
                "\"kid\": \"xl16BDxw57JN-3PtvrmyA-zWTgM\", \"kty\": \"RSA\", " +
                "\"n\": \"wNxCV2ShU99ncUqZZyT1gScdjk8Mk6nKX0ejemmueHHyVmPsGQs4B11ARL2bGi_jJabbByDfa6qyl8i-eUAbGuwf" +
                "6N1uNeBnvAIKdTIQKFlwfk6ev3-KXbwpSY53y7XQQx_Fismu1IkMWfhhJ-H-57j9vTlvbF4Ld3xAUAmKr5Zn0wMAG04tS7MyS" +
                "ruptK5aoP-fsHVAUKuSbplDzXe3dTQ0aue5yLpv1ZQc_tqOEQDpCcL4EROivBUpMvPpXupGzaAxL-N6EKPR2mGIwQatx3wW_f" +
                "t8QPw4O151g5jGSiEJJ_rJ9VCIRcPEpuQFYVcKEu5u9-2O433HKY_ITu46iQ\", \"x5t\": \"xl16BDxw57JN-3PtvrmyA-" +
                "zWTgM\", \"x5t#256\": \"e9IVUvH7-e1JuynqE7Za0J-dFveSIIoIUrJEkeAWqUk\", " +
                "\"x5u\": \"https://keystore.mit.openbanking.qa/VCLDvrRWGoRwROsuCG/xl16BDxw57JN-3PtvrmyA-zWTgM.pem\", " +
                "\"x5c\": [\"MIIFljCCBH6gAwIBAgIEWWwG0jANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJHQjEdMBsGA1UEChMUT3BlbiB" +
                "CYW5raW5nIExpbWl0ZWQxETAPBgNVBAsTCFRlc3QgUEtJMSUwIwYDVQQDExxPcGVuIEJhbmtpbmcgVGVzdCBJc3N1aW5nIENBMB" +
                "4XDTE3MTIyMjEwMTMxNVoXDTE5MDEyMjEwNDMxNVowYDELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pd" +
                "GVkMREwDwYDVQQLEwhUZXN0IFBLSTEfMB0GA1UEAxMWNmRpMkRlODhzOEQyelZYZ3l4bTBiMjCCASIwDQYJKoZIhvcNAQEBBQAD" +
                "ggEPADCCAQoCggEBAMDcQldkoVPfZ3FKmWck9YEnHY5PDJOpyl9Ho3pprnhx8lZj7BkLOAddQES9mxov4yWm2wcg32uqspfIvnl" +
                "AGxrsH+jdbjXgZ7wCCnUyEChZcH5Onr9/il28KUmOd8u10EMfxYrJrtSJDFn4YSfh/ue4/b05b2xeC3d8QFAJiq+WZ9MDABtOLU" +
                "uzMkq7qbSuWqD/n7B1QFCrkm6ZQ813t3U0NGrnuci6b9WUHP7ajhEA6QnC+BETorwVKTLz6V7qRs2gMS/jehCj0dphiMEGrcd8F" +
                "v37fED8ODtedYOYxkohCSf6yfVQiEXDxKbkBWFXChLubvftjuN9xymPyE7uOokCAwEAAaOCAlAwggJMMA4GA1UdDwEB/wQEAwIG" +
                "wDAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMIHgBgNVHSAEgdgwgdUwgdIGCysGAQQBqHWBBgFkMIHCMCoGCCsGAQUFBwIBFh5odHR" +
                "wOi8vb2IudHJ1c3Rpcy5jb20vcG9saWNpZXMwgZMGCCsGAQUFBwICMIGGDIGDVXNlIG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3" +
                "RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgT3BlbkJhbmtpbmcgUm9vdCBDQSBDZXJ0aWZpY2F0aW9uIFBvbGljaWVzIGFuZCBDZ" +
                "XJ0aWZpY2F0ZSBQcmFjdGljZSBTdGF0ZW1lbnQwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzABhh5odHRwOi8vb2J0ZXN0LnRy" +
                "dXN0aXMuY29tL29jc3AwgcMGA1UdHwSBuzCBuDA3oDWgM4YxaHR0cDovL29idGVzdC50cnVzdGlzLmNvbS9wa2kvb2J0ZXN0aXN" +
                "zdWluZ2NhLmNybDB9oHugeaR3MHUxCzAJBgNVBAYTAkdCMR0wGwYDVQQKExRPcGVuIEJhbmtpbmcgTGltaXRlZDERMA8GA1UECx" +
                "MIVGVzdCBQS0kxJTAjBgNVBAMTHE9wZW4gQmFua2luZyBUZXN0IElzc3VpbmcgQ0ExDTALBgNVBAMTBENSTDgwHwYDVR0jBBgwF" +
                "oAUDwHAL+hobPcjv45lbokNxqaFd7cwHQYDVR0OBBYEFNczbyn1OqOJZ1kAJRrwLmomI9JVMA0GCSqGSIb3DQEBCwUAA4IBAQBB" +
                "hSq283S2SfvnjeWpp3nkOEP4SLORINjyUuWjt/ivHSnHBJVlVCKyB05BQyyImNUXFtvQD0Hn2k+OTPmPprtPbWVMUaIrTa2aGmC" +
                "bNLhp5ukPc1GCzSSzR4lpmNOHbL0wxV0uG4Kb+qrSQZlfwx8KmeogYeaZVOTE6rfzydnNkUi7CJ7AWeOl/aUyIN0w9PDxGAWfa+" +
                "YS0efx7UwXrv3pitEGo/zP/4Tygsd2lgvlJ/xml2nyVM4oCv5WTyZTMxeC/zqcUTouvogJcIqyKcZHSlKaKNQgNaT1Ury9mPGXP" +
                "i7MraTBB1hFY4g4JDQ5c6YRISoA8pOXyFLIG4zxIrqu\"], " +
                "\"use\": \"sig\"}, " +
                "{\"e\": \"AQAB\", \"kid\": \"2bag3Pig0ajRgDs8HLF0qNsIoy0\", \"kty\": \"RSA\", " +
                "\"n\": \"t-nDTUa8Ay22jFSVn3dG3Fzcmbjv4tcMovNooIgB3SeMAfpHhjKWj7yFVhyGUbQrmEqFoZB8AR0fEfU_cplx22SyhS" +
                "MbwAlMsud7eXFpaf9hp28u-O9tNortyuGD81cIMA1t2d8UOOW3hyjfFBpPgIlm7LmXco95iLum4auJwVwYQu0xE2Xz7xbRyle39" +
                "XhHWOIvA39re3Cj7_VCvk1fyshYDrWFVnlMSOJATqqNXwoxsY9K6IfAchj1EJU8N0CNLhu1BpyjHM7qrrDP-mEE6FLAWEpe6rzu" +
                "pRcpIWLkRoUol17jVULNHfp5NPgiTxBPsEZybIjnnxI-E2Og4VXJjw\", " +
                "\"x5t\": \"2bag3Pig0ajRgDs8HLF0qNsIoy0\", " +
                "\"x5t#256\": \"IXbL0R9gp9qpbLYMc_wnQTtC61pVLkQaxMry7jbLE58\", " +
                "\"x5u\": \"https://keystore.mit.openbanking.qa/VCLDvrRWGoRwROsuCG/2bag3Pig0ajRgDs8HLF0qNsIoy0.pem\", " +
                "\"x5c\": [\"MIIFoTCCBImgAwIBAgIEWWwHrzANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJHQjEdMBsGA1UEChMUT3BlbiB" +
                "CYW5raW5nIExpbWl0ZWQxETAPBgNVBAsTCFRlc3QgUEtJMSUwIwYDVQQDExxPcGVuIEJhbmtpbmcgVGVzdCBJc3N1aW5nIENBMB" +
                "4XDTE3MTIyNzEyNTcwNloXDTE4MTIyNzEzMjcwNlowYDELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pd" +
                "GVkMREwDwYDVQQLEwhUZXN0IFBLSTEfMB0GA1UEAxMWNmRpMkRlODhzOEQyelZYZ3l4bTBiMjCCASIwDQYJKoZIhvcNAQEBBQAD" +
                "ggEPADCCAQoCggEBALfpw01GvAMttoxUlZ93Rtxc3Jm47+LXDKLzaKCIAd0njAH6R4Yylo+8hVYchlG0K5hKhaGQfAEdHxH1P3K" +
                "ZcdtksoUjG8AJTLLne3lxaWn/YadvLvjvbTaK7crhg/NXCDANbdnfFDjlt4co3xQaT4CJZuy5l3KPeYi7puGricFcGELtMRNl8+" +
                "8W0cpXt/V4R1jiLwN/a3two+/1Qr5NX8rIWA61hVZ5TEjiQE6qjV8KMbGPSuiHwHIY9RCVPDdAjS4btQacoxzO6q6wz/phBOhSw" +
                "FhKXuq87qUXKSFi5EaFKJde41VCzR36eTT4Ik8QT7BGcmyI558SPhNjoOFVyY8CAwEAAaOCAlswggJXMA4GA1UdDwEB/wQEAwIH" +
                "gDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwY" +
                "BBQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aW" +
                "ZpY2F0ZSBjb25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9sa" +
                "WNpZXMgYW5kIENlcnRpZmljYXRlIFByYWN0aWNlIFN0YXRlbWVudDA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6" +
                "Ly9vYnRlc3QudHJ1c3Rpcy5jb20vb2NzcDCBwwYDVR0fBIG7MIG4MDegNaAzhjFodHRwOi8vb2J0ZXN0LnRydXN0aXMuY29tL3B" +
                "raS9vYnRlc3Rpc3N1aW5nY2EuY3JsMH2ge6B5pHcwdTELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pdG" +
                "VkMREwDwYDVQQLEwhUZXN0IFBLSTElMCMGA1UEAxMcT3BlbiBCYW5raW5nIFRlc3QgSXNzdWluZyBDQTENMAsGA1UEAxMEQ1JMO" +
                "DAfBgNVHSMEGDAWgBQPAcAv6Ghs9yO/jmVuiQ3GpoV3tzAdBgNVHQ4EFgQUlEi3t97ynfKhOYbFWNtcKIC0vbkwDQYJKoZIhvcN" +
                "AQELBQADggEBAAqdNuOUgln2j1Ar1V1JyAe2B/2Fa5gMxAKxWJ4DC1bi6G0R9sArsCSswkOu0Deo2g9uqKJS6FAaqghJEnmU4VO" +
                "J9+PZ85oJTrQAvxtQH3wJk/sJjKtE5Di4zOBLfyVGRosqlvVlqHtSGE5kf/ncrfRzBAyuf2szJHsoT4OiNB3lMcfSWPGVT86g9N" +
                "pAEdJptW0SCqQ4X9EhSx59hNPngt2oHC//yZpbOcfdNV8PlyQREZ4wCNvUsM+9z6R7smfnVv+ILogXr9sgdEKzjUvJmIBaS0QNb" +
                "DyGR9519AYxKPuVhSc7Ik7gxAWcenQJml8B0nivERubRh4AUXSDanBXHB4=\"], \"use\": \"enc\"}]}";
        JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);

        JsonWebKey jsonWebKey = jwks.findJsonWebKey("xl16BDxw57JN-3PtvrmyA-zWTgM", null, null, null);
        String thumbprint = jsonWebKey.calculateBase64urlEncodedThumbprint("SHA1");
        assertThat("xl16BDxw57JN-3PtvrmyA-zWTgM", equalTo(thumbprint));

        jsonWebKey = jwks.findJsonWebKey("2bag3Pig0ajRgDs8HLF0qNsIoy0", null, null, null);
        thumbprint = jsonWebKey.calculateBase64urlEncodedThumbprint("SHA1");
        assertThat("2bag3Pig0ajRgDs8HLF0qNsIoy0", equalTo(thumbprint));
    }

}
