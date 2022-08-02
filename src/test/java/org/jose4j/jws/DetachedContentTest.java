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

package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class DetachedContentTest
{
    @Test
    public void testSomeDetachedContent() throws Exception
    {
        String payload = "Issue #48";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        String detachedContentCompactSerialization = jws.getDetachedContentCompactSerialization();
        String encodedPayload = jws.getEncodedPayload();
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedContentCompactSerialization);
        jws.setEncodedPayload(encodedPayload);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));

        jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedContentCompactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertFalse(jws.verifySignature());
    }

    @Test
    public void testVerifyDetachedUnencodedContentButSignatureOverEncoded() throws Exception {

        // the detached payload was conveyed unencoded but the signature was traditional JWS over the encoded
        // jose4j couldn't verify due to empty string / null mixup
        // https://bitbucket.org/b_c/jose4j/issues/194/verifying-jws-with-detached-payload-using
        // https://stackoverflow.com/questions/70380691/verifying-jws-with-detached-payload-using-jose4j-fails

        String payload = "{\"paymentId\":\"d927a7c8cca3392907808ef2\",\"transferAmount\":1310,\"tippingAmount\":0,"
                + "\"amount\":1310,\"totalAmount\":1310,\"description\":\"Invoice Payment\",\"reference\":\"0006-485\","
                + "\"createdAt\":\"2021-12-16T13:41:08.726Z\",\"expireAt\":\"2031-12-16T23:53:08.726Z\",\"succeededAt\":\"2021-12-16T13:41:20.189Z\","
                + "\"status\":\"SUCCEEDED\",\"debtor\":{\"name\":\"Koen\",\"iban\":\"*************24680\"},\"currency\":\"EUR\"}";

        String signature = "eyJ0eXAiOiJKT1NFK0pTT04iLCJraWQiOiJlcy5zaWduYXR1cmUuZXh0LjIwMjIiLCJhbGciOiJFUzI1NiIsImh0d"
                + "HBzOi8vcGF5Y29uaXEuY29tL2lhdCI6IjIwMjEtMTItMTZUMTM6NDE6MjAuMjA5NTU0WiIsImh0dHBzOi8vcGF5Y29uaXEuY29tL2p0aSI"
                + "6IjIzZjVhNzVkMTNmYWMzOWEiLCJodHRwczovL3BheWNvbmlxLmNvbS9wYXRoIjoiaHR0cHM6Ly90ZXN0Mi5zb25ldGFzLmV1L2Z1Z2Evc"
                + "mVzdC9wYXljb25pcS9pbnZvaWNlUGF5bWVudCIsImh0dHBzOi8vcGF5Y29uaXEuY29tL2lzcyI6IlBheWNvbmlxIiwiaHR0cHM6Ly9wYXl"
                + "jb25pcS5jb20vc3ViIjoiNjFiMDcxNThkZjUwODkwMDA3ZGM3Y2NhIiwiY3JpdCI6WyJodHRwczovL3BheWNvbmlxLmNvbS9pYXQiLCJod"
                + "HRwczovL3BheWNvbmlxLmNvbS9qdGkiLCJodHRwczovL3BheWNvbmlxLmNvbS9wYXRoIiwiaHR0cHM6Ly9wYXljb25pcS5jb20vaXNzIiw"
                + "iaHR0cHM6Ly9wYXljb25pcS5jb20vc3ViIl19..AZCpJ_3M8fKyK_sQ0XS9ifdCnZUiQHReQ7owWhVdrfs90mFj66z9XEh-Fcl_IteSUgR"
                + "JU7-TrLDdEfrISvG0lw";

        String[] critHeaders = {
                "https://payconiq.com/sub",
                "https://payconiq.com/iss",
                "https://payconiq.com/iat",
                "https://payconiq.com/jti",
                "https://payconiq.com/path"
        };

        String key = "{"
                + "\"kty\": \"EC\","
                + "\"use\": \"sig\","
                + "\"x5t#S256\": \"IZOqCxLESbQkCaObdW1kxMPgV5VFGb9nFkjiwL0G_eg\","
                + "\"crv\": \"P-256\","
                + "\"kid\": \"es.signature.ext.2022\","
                + "\"alg\": \"ES256\","
                + "\"x5c\": ["
                + "\"MIIE1zCCBH2gAwIBAgIQHzgeQOjemgrfp6IwTS5XfzAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIEVDQyBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMB4XDTIxMTEyMzAwMDAwMFoXDTIyMTIyNDIzNTk1OVowKDEmMCQGA1UEAxMdZXMuc2lnbmF0dXJlLmV4dC5wYXljb25pcS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARIpLe02lsuMs6G1lQQRw3Zo4GlBwxi1h7EDD6GC9MxYRkkxOQMrJ1UKD3ni4dXcCZjHyv2GGvWhNICOaCso9Elo4IDHzCCAxswHwYDVR0jBBgwFoAU9oUKOxGG4QR9DqoLLNLuzGR7e64wHQYDVR0OBBYEFHUsvJY0jGLPbsoGZeOmkk09+ADEMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBJBgNVHSAEQjBAMDQGCysGAQQBsjEBAgIHMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAECATCBhAYIKwYBBQUHAQEEeDB2ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29FQ0NEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTBLBgNVHREERDBCgh1lcy5zaWduYXR1cmUuZXh0LnBheWNvbmlxLmNvbYIhd3d3LmVzLnNpZ25hdHVyZS5leHQucGF5Y29uaXEuY29tMIIBewYKKwYBBAHWeQIEAgSCAWsEggFnAWUAdQBGpVXrdfqRIDC1oolp9PN9ESxBdL79SbiFq/L8cP5tRwAAAX1MZuRtAAAEAwBGMEQCIErmMHlQjPe/aNTo08NiFGS2hlKeBU5Ubrl9OG7myLWcAiB4bWXL8HOl2oNVci3Cv0RMnNTyMHIrAm8Lw9QQq/UxTQB1AEHIyrHfIkZKEMahOglCh15OMYsbA+vrS8do8JBilgb2AAABfUxm5DUAAAQDAEYwRAIgNEbgqCHIAjLqhRGBmiHRAqNwX5qI1GSlfAbqVq4V/W0CIHRCmucjmXpbVKzPsOfJ6RBPHWSUJJSjiGLf1QTtvliDAHUAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF9TGbj/QAABAMARjBEAiAlPQGU1X34G+wtrYEpGFodWifIfxfeOwKx9o3qjVr4LAIgUQenz7z8a0zIC5XATCAwEG3uXnbATrl+ss5cu6YqvPowCgYIKoZIzj0EAwIDSAAwRQIhAN5vKyEhzWAj6Wc6bhr8l9YXIGn4e4dNVSYeHcRoK0AkAiAhhXJkG+SzWyp/bFJeCfXbnWw59mww9GOOkoNizKCG6w==\","
                + "\"MIIDqDCCAy6gAwIBAgIRAPNkTmtuAFAjfglGvXvh9R0wCgYIKoZIzj0EAwMwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UEAxMuU2VjdGlnbyBFQ0MgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHkYk8qfbZ5sVwAjBTcLXw9YWsTef1Wj6R7W2SUKiKAgSh16TwUwimNJE4xkIQeV/To14UrOkPAY9z2vaKb71EijggFuMIIBajAfBgNVHSMEGDAWgBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAdBgNVHQ4EFgQU9oUKOxGG4QR9DqoLLNLuzGR7e64wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBsGA1UdIAQUMBIwBgYEVR0gADAIBgZngQwBAgEwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdEVDQ0NlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdEVDQ0FkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMAoGCCqGSM49BAMDA2gAMGUCMEvnx3FcsVwJbZpCYF9z6fDWJtS1UVRscS0chWBNKPFNpvDKdrdKRe+oAkr2jU+ubgIxAODheSr2XhcA7oz9HmedGdMhlrd94ToKFbZl+/OnFFzqnvOhcjHvClECEQcKmc8fmA==\","
                + "\"MIID0zCCArugAwIBAgIQVmcdBOpPmUxvEIFHWdJ1lDANBgkqhkiG9w0BAQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthLq8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8ZncJZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5o4HyMIHvMB8GA1UdIwQYMBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zARBgNVHSAECjAIMAYGBFUdIAAwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggEBABns652JLCALBIAdGN5CmXKZFjK9Dpx1WywV4ilAbe7/ctvbq5AfjJXyij0IckKJUAfiORVsAYfZFhr1wHUrxeZWEQff2Ji8fJ8ZOd+LygBkc7xGEJuTI42+FsMuCIKchjN0djsoTI0DQoWz4rIjQtUfenVqGtF8qmchxDM6OW1TyaLtYiKou+JVbJlsQ2uRl9EMC5MCHdK8aXdJ5htN978UeAOwproLtOGFfy/cQjutdAFI3tZs4RmYCV4Ks2dH/hzg1cEo70qLRDEmBDeNiXQ2Lu+lIg+DdEmSx/cQwgwp+7e9un/jX9Wf8qn0dNW44bOwgeThpWOjzOoEeJBuv/c=\","
                + "\"MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==\""
                + "],"
                + "\"x\": \"SKS3tNpbLjLOhtZUEEcN2aOBpQcMYtYexAw-hgvTMWE\","
                + "\"y\": \"GSTE5AysnVQoPeeLh1dwJmMfK_YYa9aE0gI5oKyj0SU\""
                + "}";

        JsonWebSignature jws = new JsonWebSignature();
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(key);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256));
        jws.setKnownCriticalHeaders(critHeaders);
        jws.setCompactSerialization(signature);
        jws.setPayload(payload);
        jws.setKey(jwk.getPublicKey());
        boolean result = jws.verifySignature();
        assertTrue(jws.verifySignature());
    }

    @Test
    public void testSomeDetachedUnencodedContentButSignatureOverEncoded() throws Exception
    {
        String payload = "Grace? She passed away 30 years ago!";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        String detachedContentCompactSerialization = jws.getDetachedContentCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedContentCompactSerialization);
        jws.setPayload(payload);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));
    }
}
