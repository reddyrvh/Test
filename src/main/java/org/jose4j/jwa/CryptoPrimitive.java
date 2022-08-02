package org.jose4j.jwa;


import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import java.security.Key;
import java.security.Signature;

/**
 * A wrapper class for a crypto primitive object, such as {@link Signature} and {@link Mac}, which helps
 * them transcend abstraction layers to be accessed in places they arguably should't be.
 */
public class CryptoPrimitive
{
    private final Signature sig;
    private final Cipher cip;
    private final Mac mac;
    private final Key key;
    private final KeyAgreement kag;

    public CryptoPrimitive(Signature sig)
    {
        this(sig, null, null, null, null);
    }

    public CryptoPrimitive(Cipher cipher)
    {
        this(null, cipher, null, null, null);
    }

    public CryptoPrimitive(Mac mac)
    {
        this(null, null, mac, null, null);
    }

    public CryptoPrimitive(Key key)
    {
        this(null, null, null, key, null);
    }

    public CryptoPrimitive(KeyAgreement keyAgreement)
    {
        this(null, null, null, null, keyAgreement);
    }

    private CryptoPrimitive(Signature sig, Cipher cip, Mac mac, Key key, KeyAgreement kag)
    {
        this.sig = sig;
        this.cip = cip;
        this.mac = mac;
        this.key = key;
        this.kag = kag;
    }

    /**
     * Get the {@link Signature} object.
     *
     * @return {@link Signature} object or null if this wrapper doesn't have one.
     */
    public Signature getSignature() {
        return sig;
    }

    /**
     * Get the {@link Cipher} object.
     *
     * @return {@link Cipher} object or null if this wrapper doesn't have one.
     */
    public Cipher getCipher() {
        return cip;
    }

    /**
     * Get the {@link Mac} object.
     *
     * @return {@link Mac} object or null if this wrapper doesn't have one.
     */
    public Mac getMac() {
        return mac;
    }

    /**
     * Get the {@link Key} object.
     *
     * @return {@link Key} object or null if this wrapper doesn't have one.
     */
    public Key getKey()
    {
        return key;
    }

    /**
     * Get the {@link KeyAgreement} object.
     *
     * @return {@link KeyAgreement} object or null if this wrapper doesn't have one.
     */
    public KeyAgreement getKeyAgreement()
    {
        return kag;
    }

}
