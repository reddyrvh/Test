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

import org.jose4j.lang.StringUtil;
import org.jose4j.lang.UncheckedJoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 *  An implantation of SimpleGet (used by {@link org.jose4j.jwk.HttpsJwks}) that
 *  uses {@link java.net.URL} and {@link javax.net.ssl.HttpsURLConnection} to make
 *  basic HTTP GET requests. 
 */
public class Get implements SimpleGet
{
    private static final long MAX_RETRY_WAIT = 8000;

    private static final Logger log = LoggerFactory.getLogger(Get.class);

    private int connectTimeout = 20000;
    private int readTimeout = 20000;
    private int retries = 3;
    private long initialRetryWaitTime = 180;
    private boolean progressiveRetryWait = true;
    private SSLSocketFactory sslSocketFactory;
    private HostnameVerifier hostnameVerifier;
    private int responseBodySizeLimit = 1024 * 512;
    private Proxy proxy;

    @Override
    public SimpleResponse get(String location) throws IOException
    {
        int attempts = 0;
        log.debug("HTTP GET of {}", location);
        URL url = new URL(location);
        while (true)
        {
            try
            {
                URLConnection urlConnection = (proxy == null) ? url.openConnection() : url.openConnection(proxy);
                urlConnection.setConnectTimeout(connectTimeout);
                urlConnection.setReadTimeout(readTimeout);
                preventHttpCaching(urlConnection);

                setUpTls(urlConnection);

                HttpURLConnection httpUrlConnection = (HttpURLConnection) urlConnection;
                int code = httpUrlConnection.getResponseCode();
                String msg = httpUrlConnection.getResponseMessage();

                if (code != HttpURLConnection.HTTP_OK)
                {
                    throw new IOException("Non 200 status code ("+ code + " " + msg +") returned from " + url);
                }

                String charset = getCharset(urlConnection);

                String body = getBody(urlConnection, charset);

                Map<String,List<String>> headers = httpUrlConnection.getHeaderFields();
                SimpleResponse simpleResponse = new Response(code, msg, headers, body);
                log.debug("HTTP GET of {} returned {}", url, simpleResponse);
                return simpleResponse;
            }
            catch (SSLHandshakeException | SSLPeerUnverifiedException | FileNotFoundException | ResponseBodyTooLargeException e)
            {
                throw e;
            }
            catch (IOException e)
            {
                attempts++;
                if (attempts > retries)
                {
                    throw e;
                }
                long retryWaitTime = getRetryWaitTime(attempts);
                log.debug("Waiting {}ms before retrying ({} of {}) HTTP GET of {} after failed attempt: {}", retryWaitTime, attempts, retries, url, e);
                try { Thread.sleep(retryWaitTime); } catch (InterruptedException ie) { /* ignore */ }
            }
        }
    }

    private void preventHttpCaching(URLConnection urlConnection) {
        urlConnection.setUseCaches(false);
        urlConnection.setRequestProperty("Cache-Control", "no-cache");
    }

    private String getBody(URLConnection urlConnection, String charset) throws IOException
    {
        StringWriter writer = new StringWriter();
        try (InputStream is = urlConnection.getInputStream();
             InputStreamReader isr = new InputStreamReader(is, charset))
        {
            int charactersRead = 0;
            char[] buffer = new char[1024];
            int n;
            while (-1 != (n = isr.read(buffer)))
            {
                writer.write(buffer, 0, n);
                charactersRead += n;
                if (responseBodySizeLimit > 0 && charactersRead > responseBodySizeLimit)
                {
                    throw new ResponseBodyTooLargeException("More than " + responseBodySizeLimit + " characters have been read from the response body.");
                }
            }
            log.debug("read {} characters", charactersRead);
        }
        return writer.toString();
    }

    private void setUpTls(URLConnection urlConnection)
    {
        if (urlConnection instanceof HttpsURLConnection)
        {
            HttpsURLConnection httpsUrlConnection = (HttpsURLConnection) urlConnection;
            if (sslSocketFactory != null)
            {
                httpsUrlConnection.setSSLSocketFactory(sslSocketFactory);
            }

            if(hostnameVerifier != null)
            {
                httpsUrlConnection.setHostnameVerifier(hostnameVerifier);
            }
        }
    }

    private String getCharset(URLConnection urlConnection)
    {
        String contentType = urlConnection.getHeaderField("Content-Type");
        String charset = StringUtil.UTF_8;
        try
        {
            if (contentType != null)
            {
                for (String part : contentType.replace(" ", "").split(";")) {
                    String prefix = "charset=";
                    if (part.startsWith(prefix)) {
                        charset = part.substring(prefix.length());
                        break;
                    }
                }
                Charset.forName(charset);
            }
        }
        catch (Exception e)
        {
            log.debug("Unexpected problem attempted to determine the charset from the Content-Type ({}) so will default to using UTF8: {}", contentType, e);
            charset = StringUtil.UTF_8;
        }
        return charset;
    }

    private long getRetryWaitTime(int attempt)
    {
        if (progressiveRetryWait)
        {
            double pow = Math.pow(2, attempt - 1);
            long wait = (long) (pow * initialRetryWaitTime);
            return Math.min(wait, MAX_RETRY_WAIT);
        }
        else
        {
            return initialRetryWaitTime;
        }
    }

    /**
     * Sets a specified timeout value, in milliseconds, to be used by
     * the underlying URLConnection when opening a communications link to the resource referenced
     * by the URLConnection.  Default is 20000.
     *
     * @param connectTimeout the timeout value to be used in milliseconds
     */
    public void setConnectTimeout(int connectTimeout)
    {
        this.connectTimeout = connectTimeout;
    }

    /**
     * Sets the read timeout to the specified value, in
     * milliseconds, for the underlying URLConnection.  Default is 20000.
     * 
     * @param readTimeout the timeout value to be used in milliseconds
     */
    public void setReadTimeout(int readTimeout)
    {
        this.readTimeout = readTimeout;
    }


    /**
     * Sets the HostnameVerifier used by the underlying HttpsURLConnection.
     * @param hostnameVerifier the host name verifier
     */
    public void setHostnameVerifier(HostnameVerifier hostnameVerifier)
    {
        this.hostnameVerifier = hostnameVerifier;
    }

    /**
     * Same as {@link org.jose4j.http.Get#setTrustedCertificates(Collection)} 
     * @param certificates certificates to trust
     */
    public void setTrustedCertificates(X509Certificate... certificates)
    {
        setTrustedCertificates(Arrays.asList(certificates));
    }

    /**
     * Sets the number times to retry in the case of a request that failed for a reason
     * that potently could be recovered from. Default is 3.
     * @param retries the number of times to retry
     */
    public void setRetries(int retries)
    {
        this.retries = retries;
    }

    /**
     * Sets whether a progressively longer wait time should be used between retry attempts (up to a max of 8000). Defaut is true.
     * @param progressiveRetryWait true for a progressively longer retry wait time, false for a static retry wait time
     */
    public void setProgressiveRetryWait(boolean progressiveRetryWait)
    {
        this.progressiveRetryWait = progressiveRetryWait;
    }

    /**
     * Sets the initial wait time for retry requests. Default is 180.
     * @param initialRetryWaitTime wait time in milliseconds
     */
    public void setInitialRetryWaitTime(long initialRetryWaitTime)
    {
        this.initialRetryWaitTime = initialRetryWaitTime;
    }

    /**
     * Sets a limit on the size of the response body that will be consumed. Default is 1,024,512.
     * @param responseBodySizeLimit size limit of the response body in number of characters, -1 indicates no limit
     */
    public void setResponseBodySizeLimit(int responseBodySizeLimit)
    {
        this.responseBodySizeLimit = responseBodySizeLimit;
    }

    /**
     * Sets the certificates that will be used by the underlying HttpsURLConnection as trust anchors when validating the HTTPS certificate presented by the server.
     * 
     * When this method is used, the provided certificates become the only trusted certificates for the instance
     * (the ones from the java runtime won't be used in that context anymore).
     *
     * <p>
     * Note that only one of {@link org.jose4j.http.Get#setSslSocketFactory(SSLSocketFactory)} or {@link org.jose4j.http.Get#setTrustedCertificates(Collection)}
     * or {@link org.jose4j.http.Get#setTrustedCertificates(X509Certificate...)} should be used
     * per instance of this class as each results in the setting of the underlying SSLSocketFactory used by the HttpsURLConnection and the last
     * method to be called will effectively override
     * the others.
     * </p>
     *
     * @param certificates certificates to trust
     */
    public void setTrustedCertificates(Collection<X509Certificate> certificates)
    {
        try
        {
            TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance("PKIX");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(null, null);
            int i = 0;
            for (X509Certificate certificate : certificates)
            {
                keyStore.setCertificateEntry("alias" + i++, certificate);
            }
            trustMgrFactory.init(keyStore);
            TrustManager[] customTrustManagers = trustMgrFactory.getTrustManagers();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, customTrustManagers, null);
            sslSocketFactory = sslContext.getSocketFactory();
        }
        catch (NoSuchAlgorithmException | KeyManagementException | CertificateException | IOException | KeyStoreException e)
        {
            throw new UncheckedJoseException("Unable to initialize socket factory with custom trusted  certificates.", e);
        }
    }
    /**
     * <p>
     * Sets the SSLSocketFactory to used when creating sockets for HTTPS connections, which allows
     * for control over the details of creating and initially configuring the secure sockets such
     * as setting authentication keys, peer certificate validation, enabled cipher suites, and so on.
     * </p>
     * <p>
     * Note that only one of {@link org.jose4j.http.Get#setSslSocketFactory(SSLSocketFactory)} or {@link org.jose4j.http.Get#setTrustedCertificates(Collection)}
     * or {@link org.jose4j.http.Get#setTrustedCertificates(X509Certificate...)} should be used
     * per instance of this class as each results in the setting of the underlying SSLSocketFactory used by the HttpsURLConnection and the last
     * method to be called will effectively override
     * the others.
     * </p>
     *
     * @param sslSocketFactory the SSLSocketFactory
     */
    public void setSslSocketFactory(SSLSocketFactory sslSocketFactory)
    {
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * Sets the Proxy through which the connection will be made with {@link java.net.URL#openConnection(Proxy)}.
     * By default no Proxy is used when making the connection - e.g. just {@link java.net.URL#openConnection()}.
     * @param proxy the Proxy through which the connection will be made
     */
    public void setHttpProxy(Proxy proxy)
    {
        this.proxy = proxy;
    }

    
    private static class ResponseBodyTooLargeException extends IOException
    {
        public ResponseBodyTooLargeException(String message)
        {
            super(message);
        }
    }
}
