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

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.JsonWebStructure;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

/**
 *
 */
public class SimpleJwtConsumerTestHelp
{
    private static final Logger log = LoggerFactory.getLogger(SimpleJwtConsumerTestHelp.class);

    public static InvalidJwtException expectProcessingFailure(String jwt, JwtConsumer jwtConsumer)
    {
        return expectProcessingFailure(jwt, null, jwtConsumer);
    }


    static InvalidJwtException expectProcessingFailure(String jwt, JwtContext jwtContext, JwtConsumer jwtConsumer)
    {

        InvalidJwtException ije = null;

        try
        {
            jwtConsumer.process(jwt);
            Assert.fail("jwt process/validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            ije = e;
            log.debug("Expected exception: {}", e.toString());
        }

        if (jwtContext != null)
        {
            try
            {
                jwtConsumer.processContext(jwtContext);
                Assert.fail("jwt context process/validation should have thrown an exception");
            }
            catch (InvalidJwtException e)
            {
                ije = e;
                log.debug("Expected exception: {}", e.toString());
            }
        }

        return ije;
    }

    static void goodValidate(JwtClaims jwtClaims, JwtConsumer jwtConsumer) throws InvalidJwtException
    {
        jwtConsumer.validate(new JwtContext(jwtClaims, Collections.<JsonWebStructure>emptyList()));
    }

    static void expectValidationFailureWithErrorCode(String jwt, JwtConsumer jwtConsumer, Integer errorCode)
    {
        try
        {
            jwtConsumer.process(jwt);
            Assert.fail("validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            if (errorCode != null && !e.hasErrorCode(errorCode))
            {
                Assert.fail("jwt validation exception was thrown but it didn't have error code " + errorCode + " " + e);
            }
            log.debug("Expected exception: {}", e.toString());
        }
    }

    static void expectValidationFailureWithErrorCode(JwtClaims jwtClaims, JwtConsumer jwtConsumer, Integer errorCode)
    {
        try
        {
            jwtConsumer.validate(new JwtContext(jwtClaims, Collections.<JsonWebStructure>emptyList()));
            Assert.fail("claims validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            if (errorCode != null && !e.hasErrorCode(errorCode))
            {
                Assert.fail("jwt validation exception was thrown but it didn't have error code " + errorCode + " " + e);
            }
            log.debug("Expected exception: {}", e.toString());
        }
    }

    static void expectValidationFailure(JwtClaims jwtClaims, JwtConsumer jwtConsumer)
    {
        expectValidationFailureWithErrorCode(jwtClaims, jwtConsumer, null);
    }
}
