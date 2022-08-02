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
package org.jose4j.jwt.consumer;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */
public class JwksVerificationKeyResolverUsingJwtConsumerTest
{
	private static final Logger log = LoggerFactory.getLogger(JwksVerificationKeyResolverUsingJwtConsumerTest.class);
	
    @Test
    public void idtokenFromPf() throws Exception
    {
        // JWKS from a PingFederate JWKS endpoint along with a couple ID Tokens (JWTs) it issued
        String jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhMDBrIn0." +
                "eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiUXhSYjF2Z2tpSE90MlZoNVdST0pQUiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5MzM4MiwiZXhwIjoxNDIxMDkzOTgyLCJub25jZSI6Im5hbmFuYW5hIiwiYWNyIjo" +
                "idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQiLCJhdXRoX3RpbWUiOjE0MjEwOTMzNzZ9." +
                "OlvyiduU_lZjcFHXchOzOptaBRt2XW_W2LATCPnfmi_mrfz5BsCvCGmTq6HCBBuOVF0BcbLA1h4ls3naPVu4YeWc1jkKFmlu5UwAdHP3fdUvAQdByyXDAxFgYIwl06EF-qpEX7r5_1D0OnrReq55n_SA-iqRync2nn5ZhkRoEj77E5yMFG93yRp4IP-WNZW3mZjkFPn" +
                "SCEHfRU0IBURfWkPzSkt5bKx8Vr-Oc1I5hFUyKyap8Ky17q_PoF-bHZG7MZ8B5Q5RvweVbdudain_yH3VAujDtqN_gu-7m1Vt6WdQpFIOGsVSpCK0-wtV3MvXzSKLk-5qwdVSI4GH5K_Q9g";

        String jwt2 = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMDBsIn0." +
                "eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcHoxSHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJub25jZSI6ImZmcyIsImFjciI6InVybjp" +
                "vYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDIxMDkzMzc2fQ." +
                "gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ";

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

        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder().
                setEvaluationTime(NumericDate.fromSeconds(1421093387)).
                setExpectedAudience("a").
                setExpectedIssuer("https://localhost:9031").
                setRequireExpirationTime().
                setRequireJwtId().
                setRequireSubject().
                setVerificationKeyResolver(verificationKeyResolver).build();

        JwtContext ctx = jwtConsumer.process(jwt);
        JwtClaims jwtClaims = ctx.getJwtClaims();
        assertThat(jwtClaims.getSubject(), equalTo("hailie"));

        ctx = jwtConsumer.process(jwt2);
        jwtClaims = ctx.getJwtClaims();
        assertThat(jwtClaims.getSubject(), equalTo("hailie"));

        String badJwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjhhMTBsIn0." +
                "eyJzdWIiOiJoYWlsaWUiLCJhdWQiOiJhIiwianRpIjoiRmUwZ1h1UGpmcHoxSHEzdzRaaUZIQiIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTAzMSIsImlhdCI6MTQyMTA5Mzg1OSwiZXhwIjoxNDIxMDk0NDU5LCJub25jZSI6ImZmcyIsImFjciI6InVybjp" +
                "vYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkIiwiYXV0aF90aW1lIjoxNDIxMDkzMzc2fQ." +
                "gzJQZRErEHI_v6z6dZboTPzL7p9_wXrMJIWnYZFEENgq3E1InbrZuQM3wB-mJ5r33kwMibJY7Qi4y-jvk0IYqQ";

        try
        {
            jwtClaims = jwtConsumer.processToClaims(badJwt);
            fail("shouldn't have processed/validated but got " + jwtClaims);
        }
        catch (InvalidJwtException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }
    }

    @Test
    public void someHmacOnes() throws Exception
    {
        String json = "{\"keys\":[" +
            "{\"kty\":\"oct\",\"kid\":\"uno\",  \"k\":\"i-41ccx6-7rPpCK0-i0Hi3K-jcDjt8V0aF9aWY8081d1i2c33pzq5H5eR_JbwmAojgUl727gGoKz7COz9cjic1\"}," +
            "{\"kty\":\"oct\",\"kid\":\"two\",  \"k\":\"-v_lp7B__xRr-a90cIJqpNCo7u6cY2o9Lz6-P--_01j0aF9d8bcKdrPpCK0-i0Hi3K-jcDjt8V0aF9aWY8081d\"}," +
            "{\"kty\":\"oct\",\"kid\":\"trois\",\"k\":\"i-41ccx6-7rPpCK0-i0Hi3K-jcDjt89Lz6-c_1_01ji-41ccx6-7rPpCK0-i0HiV0aF9d8bcKic10_aWY8081d\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);
        List<JsonWebKey> jsonWebKeys = jsonWebKeySet.getJsonWebKeys();
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jsonWebKeys);

        String jwtWithTrios = "eyJhbGciOiJIUzUxMiIsImtpZCI6InRyb2lzIn0" +
                ".eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTgyMDUsInN1YiI6IkFCT1VUIn0" +
                ".FtkwFqyO7nH6_FNBa-1kMGS2yx8Qabi9kQJMW2jbFWhFHYrM3VTlFIUw1Qc6znJSzLnfveix3Hi5ukc6EgIvVg";

        String jwtWithUno = "eyJhbGciOiJIUzUxMiIsImtpZCI6InVubyJ9" +
                ".eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTg0MzYsInN1YiI6IkFCT1VUIn0" +
                ".pJIcOeLWixUfePKf2ob4Piac6NByJUFlaZ5dXPoVVS1_NHIZr_9oLpFCOAe8HSqc47yO_d3bQ6mOExh1MXA6nQ";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setEvaluationTime(NumericDate.fromSeconds(1424218020))
            .setExpectedAudience("TO")
            .setExpectedIssuer("FROM")
            .setRequireExpirationTime()
            .setRequireSubject()
            .setVerificationKeyResolver(verificationKeyResolver)
            .build();

        JwtClaims claims = jwtConsumer.processToClaims(jwtWithTrios);
        assertThat("ABOUT", equalTo(claims.getSubject()));

        claims = jwtConsumer.processToClaims(jwtWithUno);
        assertThat("ABOUT", equalTo(claims.getSubject()));

        String jwtWithNope = "eyJhbGciOiJIUzUxMiIsImtpZCI6Im5vcGUifQ" +
                ".eyJpc3MiOiJGUk9NIiwiYXVkIjoiVE8iLCJleHAiOjE0MjQyMTg2NzksInN1YiI6IkFCT1VUIn0" +
                ".lZOnt-l4wIUl667laxBjZgyTZsebfitsKT1yBrEQ-DognQiqEafQaVrFTaV3dJrZDvgDqAKL9FzxOHfdBg8NXw";

        try
        {
            claims = jwtConsumer.processToClaims(jwtWithNope);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }
    }

    @Test
    public void disambiguateWithSignatureCheckOption() throws Exception
    {
        String with1stEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "04tBvYG5QeY8lniGnkZNHMW8b0OPCN6XHuK9g8fsOz8uA_r0Yk-biMkWG7ltOMCFSiiPvEu7jNWfWbk0v-hWOg";

        String with2ndEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMulM1IvKElmSyK_KBg8afywcxoApA";

        String with3rdEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "21eYfC_ZNf1FQ1Dtvj4rUiM9jYPgf1zJfeE_b2fclgu36KAN141ICqVjNxQqlK_7Wbct_FDxgyHvej_LEigb2Q";

        String with1stRsa = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "aECOQefwSdjN1Sj7LWRBV3m1uuHOFDL02nFxMWifACMELrdYZ2i9W_c6Co0SQoJ5HUE0otA8b2mXQBxJ-azetXT4YiJYBpNbKk_H52KOUWvLoOYNwrTKylWjoTprAQpCr9KQWvjn3xrCoers4N63iCC1D9mKOCrUWFzDy-" +
                "-inXDj-5VlLWfCUhu8fjx_lotgUYQVD03Rm06P3OWGz5G_oksJ7VpxDDRAYt7zROgmjFDpSWmAtNEKoAlRTeKnZZSN0R71gznBsofs-jJ8zF0QcFOuAfqHVaDWnKwqS0aduZXm0s7rH61e4OwtQdTtFZqCPldUxlfC7uzvLhxgXrdLew";

        String jwsWith2ndRsa = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "pgBu9S8g7MC2BN9YNlWD9JhjzWbQVjqpmErW4hMFncKD8bUidIbMBJSI3URXvnMJrLrAC5eB2gb6DccF_txQaqX1X81JbTSdQ44_P1W-1uIIkfIXUvM6OXv48W-CPm8xGuetQ1ayHgU_1ljtdkbdUHZ6irgaeIrFMgZX0J" +
                "db9Eydnfhwvno2oGk3y6ruq2KgKABIdzgvJXfwdOFGn1z0CxwQSVDkFRLsMsBljTwfTd0v3G8OXT8WRMZMGVyAgtKVu3XJyrPNntVqrzdgQQma6S06Y9J9V9t0AlgEAn2B4TqMxYcu1Tjr7bBL_v83zEXhbdcFBYLfJg-LY5wE6rA-dA";


        String withUnknownEC = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTEyNywiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "UE4B0IVPRip-3TDKhNAadCuj_Bf5PlEAn9K94Zd7mP25WNZwxDbQpDElZTZSp-3ngPqQyPGj27emYRHhOnFSAQ";

        String with384EC = "eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTIzMSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "NyRtG_eFmMLQ0XkW5kvdSpzYsm6P5M3U8EBFKIhD-jw8E7FOYw9PZ3_o1PWuLWH3XeArZMW7-bAIVxo2bHqJsSUtB6Tf0NWPtCpUF2c1vbuRXEXkGrCUmc4sKyOBjimC";

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

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1494437740))
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(jsonWebKeys))
                .build();

        JwtClaims claims = jwtConsumer.processToClaims(with1stEC);     // works b/c first EC p-256 in the list
        assertThat(claims.getSubject(), equalTo("me"));

        claims = jwtConsumer.processToClaims(with1stRsa);     // works b/c first RSA the list
        assertThat(claims.getSubject(), equalTo("me"));


        SimpleJwtConsumerTestHelp.expectProcessingFailure(with2ndEC, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectProcessingFailure(with3rdEC, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectProcessingFailure(withUnknownEC, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectProcessingFailure(with384EC, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwsWith2ndRsa, jwtConsumer);

        // turn on disambiguate with verify signature and the legit ones will work
        JwksVerificationKeyResolver resolver  = new JwksVerificationKeyResolver(jsonWebKeys);
        resolver.setDisambiguateWithVerifySignature(true);

        jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1494437740))
                .setExpectedAudience("the audience")
                .setExpectedIssuer("the issuer")
                .setVerificationKeyResolver(resolver)
                .build();

        claims = jwtConsumer.processToClaims(with1stEC);
        assertThat(claims.getSubject(), equalTo("me"));

        claims = jwtConsumer.processToClaims(with2ndEC);
        assertThat(claims.getSubject(), equalTo("me"));

        claims = jwtConsumer.processToClaims(with3rdEC);
        assertThat(claims.getSubject(), equalTo("me"));

        claims = jwtConsumer.processToClaims(with1stRsa);
        assertThat(claims.getSubject(), equalTo("me"));

        claims = jwtConsumer.processToClaims(jwsWith2ndRsa);
        assertThat(claims.getSubject(), equalTo("me"));

        SimpleJwtConsumerTestHelp.expectProcessingFailure(withUnknownEC, jwtConsumer);
        SimpleJwtConsumerTestHelp.expectProcessingFailure(with384EC, jwtConsumer);
    }
}
