package org.jose4j.jwt.consumer;

import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.UncheckedJoseException;

import static java.util.Locale.*;

public class TypeValidator implements ErrorCodeValidator
{
    private static final String APPLICATION_PRIMARY_TYPE = "application";

    private SimpleMediaType expectedType;
    private boolean requireType;

    public TypeValidator(boolean requireType, String expectedType)
    {
        try
        {
            this.expectedType = toMediaType(expectedType);
            if (this.expectedType.getSubType().equals("*"))
            {
                throw new UncheckedJoseException("cannot use wildcard in subtype of expected type");
            }
        }
        catch (MediaTypeParseException e)
        {
            throw new UncheckedJoseException("The given expected type '"+expectedType+"' isn't a valid media type in this context.", e);
        }
        this.requireType = requireType;
    }

    @Override
    public Error validate(JwtContext jwtContext)
    {
        JsonWebStructure jsonWebThing = jwtContext.getJoseObjects().get(0);
        String type = jsonWebThing.getHeader(HeaderParameterNames.TYPE);

        return validate(type);
    }

    Error validate(String type)
    {
        if (type == null)
        {
            return requireType ? new Error(ErrorCodes.TYPE_MISSING, "No "+HeaderParameterNames.TYPE+" header parameter present in the innermost JWS/JWE") : null;
        }

        if (expectedType != null)
        {
            try
            {
                SimpleMediaType mediaType = toMediaType(type);
                if (!expectedType.match(mediaType) || mediaType.getSubType().equals("*"))
                {
                    StringBuilder msg = new StringBuilder();
                    msg.append("Invalid typ header parameter value '").append(type).append("'. Expecting '");
                    msg.append(expectedType).append("'");
                    if (expectedType.getPrimaryType().equals(APPLICATION_PRIMARY_TYPE))
                    {
                        msg.append(" or just '").append(expectedType.getSubType()).append("'");
                    }
                    msg.append(".");
                    return new Error(ErrorCodes.TYPE_INVALID, msg.toString());
                }
            }
            catch (MediaTypeParseException e)
            {
                return new Error(ErrorCodes.TYPE_INVALID, HeaderParameterNames.TYPE + " header parameter value '"+type+"' not parsable as a media type " + e);
            }
        }

        return null;
    }

    private SimpleMediaType toMediaType(String typ) throws MediaTypeParseException
    {
        return typ.contains("/") ? new SimpleMediaType(typ) : new SimpleMediaType(APPLICATION_PRIMARY_TYPE, typ);
    }

    static class MediaTypeParseException extends Exception
    {
        MediaTypeParseException(String message)
        {
            super(message);
        }
    }

    static class SimpleMediaType
    {
        private String primaryType;
        private String subType;

        SimpleMediaType(String mediaTypeString) throws MediaTypeParseException
        {
            this.parse(mediaTypeString);
        }

        SimpleMediaType(String primary, String sub) throws MediaTypeParseException
        {
            this.primaryType = primary.toLowerCase(ENGLISH);
            checkToken(this.primaryType);
            this.subType = sub.toLowerCase(ENGLISH);
            checkToken(this.subType);
        }

        private void parse(String mediaTypeString) throws MediaTypeParseException
        {
            int slashIdx = mediaTypeString.indexOf('/');
            if (slashIdx < 0 )
            {
                throw new MediaTypeParseException("Cannot find sub type.");
            }

            int semiIdx = mediaTypeString.indexOf(';'); // don't care about the params but try and account for them

            if (semiIdx < 0)
            {
                this.primaryType = mediaTypeString.substring(0, slashIdx).trim().toLowerCase(ENGLISH);
                this.subType = mediaTypeString.substring(slashIdx + 1).trim().toLowerCase(ENGLISH);
            }
            else
            {
                if (slashIdx >= semiIdx)
                {
                    throw new MediaTypeParseException("Cannot find sub type.");
                }

                this.primaryType = mediaTypeString.substring(0, slashIdx).trim().toLowerCase(ENGLISH);
                this.subType = mediaTypeString.substring(slashIdx + 1, semiIdx).trim().toLowerCase(ENGLISH);
            }

            checkToken(this.primaryType);
            checkToken(this.subType);
        }

        String getPrimaryType()
        {
            return this.primaryType;
        }

        String getSubType()
        {
            return this.subType;
        }

        public String toString()
        {
            return this.getBaseType();
        }

        String getBaseType()
        {
            return this.primaryType + "/" + this.subType;
        }

        boolean match(SimpleMediaType type)
        {
            return this.primaryType.equals(type.getPrimaryType())
                    && (this.subType.equals(type.getSubType()) || this.subType.equals("*") || type.getSubType().equals("*"));
        }

        private static boolean isLegitTokenChar(char c)
        {
            return c > ' ' && c <= '~' && "()<>@,;:/[]?=\\\"".indexOf(c) < 0;
        }

        private static void checkToken(String t) throws MediaTypeParseException
        {
            if (t == null || t.length() == 0)
            {
                throw new MediaTypeParseException("cannot have empty part");
            }

            for (int i = 0; i < t.length(); ++i)
            {
                char c = t.charAt(i);
                if (!isLegitTokenChar(c))
                {
                    throw new MediaTypeParseException("Invalid token char " + c);
                }
            }

        }
    }
}

