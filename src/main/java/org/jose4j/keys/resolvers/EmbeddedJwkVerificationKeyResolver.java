package org.jose4j.keys.resolvers;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import java.security.Key;
import java.util.List;

/**
 * A VerificationKeyResolver implementation that uses the key in the "jwk" JWS header per
 * https://tools.ietf.org/html/rfc7515#section-4.1.3
 * <br>
 * <b>This Resolver should be used only with great care and only for specific circumstances.</b>
 *
 */
public class EmbeddedJwkVerificationKeyResolver implements VerificationKeyResolver
{
    private PublicJsonWebKey jwk;

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
    {
        try
        {
            jwk = jws.getJwkHeader();
        }
        catch (JoseException e)
        {
            throw new UnresolvableKeyException("Problem processing jwk from JWS header ("+e.getMessage()+")", e);
        }

        if (jwk == null)
        {
            throw new UnresolvableKeyException("No jwk in JWS header");
        }

        return jwk.getKey();
    }

    /**
     * Gets the JWK that was found in the JWS header by this resolver.
     * @return the JWK
     */

    public PublicJsonWebKey getJwk()
    {
        return jwk;
    }
}
