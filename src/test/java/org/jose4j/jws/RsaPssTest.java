package org.jose4j.jws;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.CryptoPrimitive;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class RsaPssTest
{
    private static final String PAYLOAD = "stuff here";

    private final String[] pssAlgs = new String[]{AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
            AlgorithmIdentifiers.RSA_PSS_USING_SHA384, AlgorithmIdentifiers.RSA_PSS_USING_SHA512};

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void roundTrips() throws Exception
    {
        final List<String> jwss = new ArrayList<>();

        final Map<String,String> legacyAlgs = new HashMap<>();
        legacyAlgs.put(AlgorithmIdentifiers.RSA_PSS_USING_SHA256, "SHA256withRSAandMGF1");
        legacyAlgs.put(AlgorithmIdentifiers.RSA_PSS_USING_SHA384, "SHA384withRSAandMGF1");
        legacyAlgs.put(AlgorithmIdentifiers.RSA_PSS_USING_SHA512, "SHA512withRSAandMGF1");

        if (hasRSASSA_PSSbyName())
        {
            for (String alg : pssAlgs)
            {
                String cs = makePssJws(alg);
                jwss.add(cs);
            }
        }

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setSignatureAlgsNeeded(pssAlgs);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String alg : pssAlgs)
                {
                    String cs = makePssJws(alg);
                    jwss.add(cs);
                }
            }
        });

        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String alg : pssAlgs)
                {
                    String cs = makePssJws(alg);
                    jwss.add(cs);

                    // and test out the Signature Algorithm Override
                    ProviderContext providerContext = new ProviderContext();
                    ProviderContext.Context suppliedKeyProviderContext = providerContext.getSuppliedKeyProviderContext();
                    String legacyAlgName = legacyAlgs.get(alg);
                    ProviderContext.SignatureAlgorithmOverride sao = new ProviderContext.SignatureAlgorithmOverride(legacyAlgName, null);
                    suppliedKeyProviderContext.setSignatureAlgorithmOverride(sao);
                    providerContext.getSuppliedKeyProviderContext().setSignatureProvider("BC");

                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setProviderContext(providerContext);
                    jws.setAlgorithmHeaderValue(alg);
                    jws.setPayload(PAYLOAD);
                    jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);

                    CryptoPrimitive cryptoPrimitive = jws.prepareSigningPrimitive();
                    log.debug("Signature underlying JWS w/setSignatureAlgorithmOverride("+
                            suppliedKeyProviderContext.getSignatureAlgorithmOverride()+"):" +
                            cryptoPrimitive.getSignature());

                    jwss.add(jws.getCompactSerialization());

                }
            }
        });


        // and test out the system property that'll force the use of the legacy rsa pss alg names
        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.setUseLegacyPssNames(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String alg : pssAlgs)
                {
                    String legacyAlgName = legacyAlgs.get(alg);

                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmHeaderValue(alg);
                    jws.setPayload(PAYLOAD);
                    jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);

                    CryptoPrimitive cryptoPrimitive = jws.prepareSigningPrimitive();
                    log.debug("Signature underlying JWS using legacy alg name system property:" +
                            cryptoPrimitive.getSignature());
                    assertThat(jws.getAlgorithm().getJavaAlgorithm(), equalTo(legacyAlgName));


                    jwss.add(jws.getCompactSerialization());
                }
            }
        });

        if (hasRSASSA_PSSbyName())
        {
            verifyJwssWithStuffHere(jwss);
        }

        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setSignatureAlgsNeeded(pssAlgs);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest() {
            @Override
            public void runTest() throws Exception {
                verifyJwssWithStuffHere(jwss);
            }
        });

        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest() {
            @Override
            public void runTest() throws Exception {
                verifyJwssWithStuffHere(jwss);

                for (String cs : jwss)
                {
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, pssAlgs));
                    jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
                    jws.setCompactSerialization(cs);

                    ProviderContext pc = new ProviderContext();
                    ProviderContext.Context suppliedKeyProviderContext = pc.getSuppliedKeyProviderContext();
                    String legacyAlgName = legacyAlgs.get(jws.getAlgorithmHeaderValue());
                    ProviderContext.SignatureAlgorithmOverride sao = new ProviderContext.SignatureAlgorithmOverride(legacyAlgName, null);
                    suppliedKeyProviderContext.setSignatureAlgorithmOverride(sao);
                    pc.getSuppliedKeyProviderContext().setSignatureProvider("BC");
                    jws.setProviderContext(pc);

                    assertTrue(jws.verifySignature());
                    assertThat(PAYLOAD, equalTo(jws.getPayload()));
                }
            }
        });

        //  test out the system property that'll force the use of the legacy rsa pss alg names
        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseLegacyPssNames(true);
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                verifyJwssWithStuffHere(jwss);

                for (String cs : jwss)
                {
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, pssAlgs));
                    jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
                    jws.setCompactSerialization(cs);

                    assertTrue(jws.verifySignature());
                    assertThat(PAYLOAD, equalTo(jws.getPayload()));
                    assertThat(legacyAlgs.get(jws.getAlgorithmHeaderValue()), equalTo(jws.getAlgorithm().getJavaAlgorithm()));
                }
            }
        });
    }

    private String makePssJws(String alg) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(alg);
        jws.setPayload(PAYLOAD);
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);

        CryptoPrimitive cryptoPrimitive = jws.prepareSigningPrimitive();
        log.debug("Signature underlying JWS w/("+ alg +"):" + cryptoPrimitive.getSignature());

        return jws.getCompactSerialization();
    }

    @Test
    public void testSomeVerifies() throws Exception
    {
        final List<String> jwss = new ArrayList<>();

        // created using BC provider and "SHAxxxwithRSAandMGF1" with a PSSParameterSpec
        jwss.add("eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.KaRX4zjLPIoT0AAK2YZ9deKyE28pZnTBS-dOaANNxpdlDrc5El99xlOD18qbPpwZDSx0iGdRTdm078LZRO6O6VRxOS9sFJl_iau-LDtHT5rPpk0BiJOH6uWE_Dr2qttdOlHaL9FwJdYJSi5Oy6BwkFulfjRMvC2i5g62FEJ4HndeIqKgCA5miwni6erjQKbN_A58_HA664uGKHziUkCzNJPQo7xcODFo1UMJflBYxMjAG6q5J-wzCX2usoWk5KrPBovEOJHAL5hw1lQJ6NV0NRBKB6ND1mYZiLzyvEIVoUYqa3C_sXaXTfjZ7jCR0EJUX7FjzaIHamnErZZpL8nZDQ");
        jwss.add("eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.XDsnCIxKsZy_Te8nToIcRvCskGE5J7sUFpYE_MflcEIZ5NLgT9SBpmLvEl9IfsJyoMxk9yH4__F5Cvl3bjcBQ8UCk4yW-P8J8MFVanyeCwtjAtwJl1So-W_Zd3DG-QpKlVaak9xE_-glgv7yNAAaRMHRrqDr1fwUnqDA7rjwq4OY_4kZh5j0Pesna6A0MAnQJusPEQUpjFN1DWzzS-f20TPoLlm-4CzXE60X8DRLs3EzeJA0SPWdOcYosikg_yZdu3HzDWL-8Cs81gbXLZLqsf2CaPakunRouOcnCSRkYhrcwv2FFxlnV29ivNWpLzjSrhplHu99d1R-xT2ZIFJ91w");
        jwss.add("eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.FZqQotC88S8E6pB08NEfIvrdwimHQAQACUWC7eBJOfSkZa52i1R2nRfI4CmcG3lEzMuYKsmREVysoDGTJWX5_X49-8Yilnq4hNBG2BN1nXwD3agRHmDNw0Pz8GgpjmK-LMcNZxSPtnLq0KnFtq1miOogFgg3xjaI21MIC0hzaE8DCvz1X82dLm_oVapjx4UivARTruME0T_4pcLsZViTkAmsg0Uu_bMOv3VWQLc-sZAl7rRPUa_dWTcAuBToPOcuxK0b6ZiM2akkDuGjbmVHEJNaKmcjWNOl0Gj6wJg5Q2R4wboKP6NxaIs2tpf1qaolVZ2COcnmGGl10kmmIVHKXw");

        // created using BC provider and "SHAxxxwithRSAandMGF1" without a PSSParameterSpec (that seems to end up using defaults that are the same)
        jwss.add("eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.WWqFutYS09AWi2K1KX-rix_yrwTgt2urJz1ZVVAHSzGLFio9WR_L6qockPFKnhmISWvN1FLmOgOLBJv9YmlUobH0ktNEXg7B03chRAt9vMgvhilExYzA_scnlOI9ZRBoThZ9TS7GazLX-NoFL9w4imm1MQkFgknkUaKHJK62VNeQZTQXqubIGw28g2SkMPU-J03mW5wM-3yK3wNgzcW_3VJyDGdnNnkVMu4o1Za17zlzxJxCVHkBih2nLCqiPO7OPrSEnq5F6pw6V4PN1UGQz9aKRy_IgnEvNxI6y8JDRDSWSf80rYHCvfbUVbrP7H-COWc_VpplgXY9_vnX6_GX0w");
        jwss.add("eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.eOrEcpfGhsBuBjvwUQNp8KEyJiQuNbmRbYLTAnlCtkScUb7ZSBqe7mlDyaym8uOHHkedhuwz-5BDlbWzkZ7ISgUNm2g6e3xS-nhVnOr8ttWQ7dpsQeSspxohKafZfg6rAcyYrsljf41hhQfVVv-PBNe5fxEq8DKC-h3xFil4LmZ5XEEeMSlAo5tU8g-BsWRpVk7qhXIncRHFsCPPBjN7gu-OU-JHCLkNdkp9wW1MJuLXUduKnP1aXW7FZji7ZyzQYXvpVA5vUAdFY9Zz_cM0QppwiaPew66D_LfaSKwzSMB55nAc6gvpDfP_D3iAlrT47ZBofvPjYQejKdN4WK1_Tg");
        jwss.add("eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.e6twRBcgDBYw8vw_Lqn0w9v-MiD5Tr8ovCMvlezeUt829zvgP2_9oY-azvHr6f15B9w7ehLFJt4nbBUuOMt4IrsEDxAB3puLA7bsHJCfE-2vNC6QrkG3uPDqPRGPGSL30gDUAOL3y6WHsXuAckDJnEgtAQsLWHi8ctiDt_9-jfskL0uimEoWhThsThjI9vKp0QuQO2Bw_c0Y7BcbTzNU1DP3FEtUJT-je0d7K8TrKaidzRRqOykvNbfcad6w29xg0PQYb7ImfWY7FxCIBUpFkHJT4HR4upJ6aEVS9SojB-tAM9jqiW5OI9ABHQE0ZUYcbPdR1xKG3nGcCx36YVQy3Q");

        // created using SUN provider with Java 11 and "RSASSA-PSS"
        jwss.add("eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.dZsMbU_NTVxZcLVY4kXoWhwpFh9kCm67RdeiLLJ8Kq4EW8zCcjbWvqe-vc76ImLuJ5nFGUnGq_g4VwDicDAiEODMyf7Bj2-FJ4X_HizvJcCoidb0vpkLl2cAoYiRBA0fpfQoMgs-H_ml9Ow6sQXGf13QWl0e_NxW3giVsiHimBR4Grkvj1u5LVfdlY_-1R2P8D9DWOpL7nNtKCVdzz5fsKDK31u7uyKLwpGMfpqyWl0X7Q9tyS7saqwCx996NLvdW7sfSuAyzX_-Mig67Y4-ZIPQbgEjfEV8cuMKSQdVmsYOJIc2AYnQRt1mA1WC3N7DhcZlUlEOdkatolPUD-NbDg");
        jwss.add("eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.hmAy5kD5TNGKxzp_6_-pbD4fVVW-xpGDrlfG3h6wijtnTrjV8QtD_qZEru87NcxACZqqgmMQeSuPIl20upseMNEvPWLX9xtUlgyEYUSo8AwO7ouD8oZNAhaqFoyTvoh7D9-CxBYsbpu9pcLFvPnBg5wT7mzadbgH94w8tCL7kT5C9rwWLcOdWU-s_0wY1CRAxbgbZZEA6EDjJbQ4krGuJPF20Lir7ERqIWEeZ1f3SGg5FPCSE1geSL5x0ggEYKKeMqDyhWYfWEe0ZT6_a-TMge_JU8OWq3BckeHnGQJadRy_eI41cs4iESDehFygjhzWdEewcHfuxV_ozN5UhiZzCw");
        jwss.add("eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.ImpuH6M3mrX0-qmALLT1oLTJY4cj9byPRbXF18QVL2Uz4ij5qkx1IWljqPcidhEtg5PqYqESAl4Jh0kxPDBoVrGr9x5lwOKfGJUkLepi8o38UmgreW7OsCU9KZ3dX5G6s9dCPYX7lwRRBACxy_BFz9NNIBX2R2xx1GbrsQsiX8v4e2b8O3EigfwnRmvnjsm1cH4CK6prb_CVy579qSiDQJ1Qc5bIBAgVEYR-El4zJ106OxOfB9b0RStQAJ_0FYtHXSqTs8IoS_PCAeroqf1Id08fby8b4gypuB5o-n8FRBdfKaVTbLA04C3qmoj0uImKx5EHWOlLVAH2k5EirkredA");

        if (hasRSASSA_PSSbyName()) // java 11 + will use the sun/oracle provider for PSS
        {
            verifyJwssWithStuffHere(jwss);
        }

        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setSignatureAlgsNeeded(pssAlgs); // will chose based on what is available
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                verifyJwssWithStuffHere(jwss);
            }
        });


        jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setUseBouncyCastleRegardlessOfAlgs(true); // force BC
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                verifyJwssWithStuffHere(jwss);
            }
        });


    }

    private void verifyJwssWithStuffHere(List<String> jwss) throws JoseException {
        for (String cs : jwss)
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, pssAlgs));
            jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
            jws.setCompactSerialization(cs);

            assertTrue(jws.verifySignature());
            assertThat(PAYLOAD, equalTo(jws.getPayload()));
        }
    }

    private boolean hasRSASSA_PSSbyName() // which implies > Java 11 (or later versions >= u251 of 8 apparently)
    {
        Set<String> sigAlgs = Security.getAlgorithms("Signature");
        return sigAlgs.contains(RsaUsingShaAlgorithm.RSASSA_PSS);
    }
}
