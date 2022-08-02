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

package org.jose4j.keys;

import junit.framework.TestCase;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 */
public class EllipticCurvesTest
{
    @Test
    public void testGetName() throws Exception
    {
        String b64d = "MIIBbjCCARKgAwIBAgIGAT0hzf2zMAwGCCqGSM49BAMCBQAwPDENMAsGA1UEBhMEbnVsbDErMCkGA1UEAxMiYXV0by1nZW5lcmF0ZWQgd3JhcHBlciBjZXJ0aWZpY2F0ZTAeFw0xMzAyMjgxNzE2MjBaFw0xNDAyMjgxNzE2MjBaMDwxDTALBgNVBAYTBG51bGwxKzApBgNVBAMTImF1dG8tZ2VuZXJhdGVkIHdyYXBwZXIgY2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARwLMpLp9BHKkFoGUE25feUccsQMJQY8JlFV7DIC596FBdjvcbxvfiStEDkcA4WOZThyQnPZlrPKqc2A4QuQRDmMAwGCCqGSM49BAMCBQADSAAwRQIhAPladiFs6XVS7fqfuvC8DEY0kmaoKWuGE30AA88NsIYzAiB9gUEGxDjEiLrjgjl9ds7n+7iBDhS4C5V2MpTG2QND5A==";
        X509Util x5u = new X509Util();
        X509Certificate x509Certificate = x5u.fromBase64Der(b64d);

        PublicKey publicKey = x509Certificate.getPublicKey();
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        String name = EllipticCurves.getName(ecPublicKey.getParams().getCurve());
        Assert.assertEquals(EllipticCurves.P_256, name);
    }

    @Test
    public void testNames() throws Exception
    {
        // Test my names and the EllipticCurves class against the 'standard name' which I didn't know about
        // but someone pointed me to "Implementing ECC with Java Standard Edition 7" at http://www.academicpub.org/PaperInfo.aspx?PaperID=14496
        // which educated me a bit
        Map<String,String> names = new LinkedHashMap<>();
        names.put("secp256r1", EllipticCurves.P_256);
        names.put("secp384r1", EllipticCurves.P_384);
        names.put("secp521r1", EllipticCurves.P_521);

        for (Map.Entry<String,String> e : names.entrySet())
        {
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(e.getKey());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(ecGenParameterSpec);
            KeyPair keyPair = kpg.generateKeyPair();
            ECPublicKey ecpub = (ECPublicKey) keyPair.getPublic();
            ECParameterSpec params = ecpub.getParams();
            Assert.assertEquals(e.getValue(), EllipticCurves.getName(params.getCurve()));
        }
    }
}
