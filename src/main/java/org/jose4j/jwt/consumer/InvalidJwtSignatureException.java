package org.jose4j.jwt.consumer;

import org.jose4j.jws.JsonWebSignature;

import java.util.Collections;

/**
 *
 */
public class InvalidJwtSignatureException extends InvalidJwtException
{
    public InvalidJwtSignatureException(JsonWebSignature jws, JwtContext jwtContext)
    {
        super("JWT rejected due to invalid signature.",
                Collections.singletonList(new ErrorCodeValidator.Error(ErrorCodes.SIGNATURE_INVALID, "Invalid JWS Signature: " + jws)),
                jwtContext);
    }
}
