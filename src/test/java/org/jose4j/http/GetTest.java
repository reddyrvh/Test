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
package org.jose4j.http;

import org.jose4j.keys.X509Util;
import org.junit.Ignore;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Calling external URLs so these tests are more to use for manual stuff rather than part of the normal unit tests.  hence the @Ignore
 * todo consider tests that would be more suitable (spin up a little jetty instances or something?)
 */
@Ignore
public class GetTest
{
    @Test
    public void localPF() throws Exception
    {
        X509Util x509Util = new X509Util();
        X509Certificate certificate = x509Util.fromBase64Der(
                "MIICUDCCAbkCBETczdcwDQYJKoZIhvcNAQEFBQAwbzELMAkGA1UEBhMCVVMxCzAJ\n" +
                "BgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxFTATBgNVBAoTDFBpbmdJZGVudGl0\n" +
                "eTEXMBUGA1UECxMOQnJpYW4gQ2FtcGJlbGwxEjAQBgNVBAMTCWxvY2FsaG9zdDAe\n" +
                "Fw0wNjA4MTExODM1MDNaFw0zMzEyMjcxODM1MDNaMG8xCzAJBgNVBAYTAlVTMQsw\n" +
                "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRp\n" +
                "dHkxFzAVBgNVBAsTDkJyaWFuIENhbXBiZWxsMRIwEAYDVQQDEwlsb2NhbGhvc3Qw\n" +
                "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJLrpeiY/Ai2gGFxNY8Tm/QSO8qg\n" +
                "POGKDMAT08QMyHRlxW8fpezfBTAtKcEsztPzwYTLWmf6opfJT+5N6cJKacxWchn/\n" +
                "dRrzV2BoNuz1uo7wlpRqwcaOoi6yHuopNuNO1ms1vmlv3POq5qzMe6c1LRGADyZh\n" +
                "i0KejDX6+jVaDiUTAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAMojbPEYJiIWgQzZc\n" +
                "QJCQeodtKSJl5+lA8MWBBFFyZmvZ6jUYglIQdLlc8Pu6JF2j/hZEeTI87z/DOT6U\n" +
                "uqZA83gZcy6re4wMnZvY2kWX9CsVWDCaZhnyhjBNYfhcOf0ZychoKShaEpTQ5UAG\n" +
                "wvYYcbqIWC04GAZYVsZxlPl9hoA=\n");

        X509Certificate otherCert = x509Util.fromBase64Der(
                "MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL\n" +
                "MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC\n" +
                "VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx\n" +
                "NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD\n" +
                "TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu\n" +
                "ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j\n" +
                "V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj\n" +
                "gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA\n" +
                "FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE\n" +
                "CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS\n" +
                "BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE\n" +
                "BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju\n" +
                "Wm7DCfrPNGVwFWUQOmsPue9rZBgO\n");

        String location = "https://localhost:9031/pf/JWKS";

        Get get = new Get();
        get.setTrustedCertificates(certificate, otherCert);
        get.setReadTimeout(200);
        get.setRetries(5);
        get.setProgressiveRetryWait(true);
        SimpleResponse simpleResponse = get.get(location);
        System.out.println(simpleResponse);
    }

    @Test
    public void localPFUsingSocketFactoryWithTrustAnything() throws Exception
    {
        String location = "https://localhost:9031/pf/JWKS";

        TrustManager[] tms = new TrustManager[] { new X509TrustManager()
        {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException { }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException { }

            @Override
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }};

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tms, null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        Get get = new Get();
        get.setSslSocketFactory(sslSocketFactory);
        get.setReadTimeout(200);
        get.setRetries(5);
        get.setProgressiveRetryWait(true);
        SimpleResponse simpleResponse = get.get(location);
        System.out.println(simpleResponse);
    }

    @Test
    public void googlesJWKS() throws Exception
    {
        String location = "https://www.googleapis.com/oauth2/v3/certs";
        Get get = new Get();
        SimpleResponse simpleResponse = get.get(location);
        System.out.println(simpleResponse);
    }

    @Test
    public void followRedirect() throws Exception
    {
        String location = "http://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%2F";
        Get get = new Get();
        SimpleResponse simpleResponse = get.get(location);  // redirects to example.com
        System.out.println(simpleResponse);
    }
}
