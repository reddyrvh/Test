package org.jose4j.jwt.consumer;

import org.jose4j.lang.UncheckedJoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

public class TypeValidatorTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void validateExamplePlusJwt()
    {
        for (String expected : new String[] {"application/example+jwt", "example+jwt", "EXAMPLE+JWT", "application/example+JWT"})
        {
            for (boolean require : new boolean[] {true, false})
            {
                TypeValidator tv = new TypeValidator(require, expected);

                nope(tv, "nope+jwt");
                nope(tv, "application/nope+jwt");
                nope(tv, "howaboutno");
                nope(tv, "*");
                nope(tv, "application/*");
                nope(tv, "application/*+jwt");
                nope(tv, "jwt+example");

                yep(tv, "application/example+jwt");
                yep(tv, "example+jwt");
                yep(tv, "application/EXAMPLE+JWT");
                yep(tv, "application/example+JWT");
                yep(tv, "example+JWT");
                yep(tv, "Example+jwt");
                yep(tv, "example+JWT");
            }
        }
    }

    @Test
    public void validateDpopPlusJwt()
    {
        for (String expected : new String[] {"application/dpop+jwt", "dpop+jwt", "DPoP+jwt", "dpop+JWT"})
        {

            for (boolean require : new boolean[] {true, false})
            {
                TypeValidator tv = new TypeValidator(require, expected);

                nope(tv, "nope+jwt");
                nope(tv, "application/nope+jwt");
                nope(tv, "nonono");
                nope(tv, "*");
                nope(tv, "application/*");
                nope(tv, "application/*+jwt");
                nope(tv, "jwt+example");
                nope(tv, "example+jwt");
                nope(tv, "[[meh");
                nope(tv, "no;no;no");


                yep(tv, "application/dpop+jwt");
                yep(tv, "dpop+jwt");
                yep(tv, "application/DPOP+JWT");
                yep(tv, "application/DPoP+JWT");
                yep(tv, "DPOP+JWT");
                yep(tv, "dPOP+jwt");
                yep(tv, "dpop+JWT");

                if (require)
                {
                    nope(tv, null, ErrorCodes.TYPE_MISSING);
                }
                else
                {
                    yep(tv, null);
                }
            }
        }
    }


    @Test
    public void expectedValuesNotOkay()
    {
        for (String expectedType : new String[] {"application/noway)", "/", "/dpop+jwt", "", "*", "application/*", "image/*"})
        {
            try
            {
                TypeValidator typeValidator = new TypeValidator(true, expectedType);
                fail("shouldn't work with " + expectedType + " but " + typeValidator);
            }
            catch (UncheckedJoseException e)
            {
                log.debug("Expected " + e);
            }
        }
    }

    private void yep(TypeValidator typeValidator, String headerValue)
    {
        ErrorCodeValidator.Error error = typeValidator.validate(headerValue);
        assertNull("validation should have been ok but " + error, error);
    }

    private void nope(TypeValidator typeValidator, String headerValue, int expectedErrorCode)
    {
        ErrorCodeValidator.Error error = typeValidator.validate(headerValue);
        log.debug("Expected validation error: " + error);
        assertNotNull("should have returned an error" , error);
        assertThat(expectedErrorCode, equalTo(error.getErrorCode()));
    }


    private void nope(TypeValidator typeValidator, String headerValue)
    {
        nope(typeValidator, headerValue, ErrorCodes.TYPE_INVALID);
    }
}