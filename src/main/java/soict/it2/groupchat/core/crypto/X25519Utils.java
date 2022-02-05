package soict.it2.groupchat.core.crypto;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

public class X25519Utils {

    public static byte[] exchange(XECKeyPair myKeyPair, XECPublicKey theirPublicKey) {
        KeyAgreement keyAgreement;
        try {
            keyAgreement = KeyAgreement.getInstance("XDH");
            keyAgreement.init(myKeyPair.getPrivate());
            keyAgreement.doPhase(theirPublicKey, true);
            return keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static XECKeyPair newKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            generator.initialize(NamedParameterSpec.X25519);
            KeyPair keyPair = generator.genKeyPair();
            return new XECKeyPair((XECPublicKey) keyPair.getPublic(), (XECPrivateKey) keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static XECKeyPair fromPrivateKey(XECPrivateKey privateKey) {
        byte[] rawPrivateKey = privateKey.getScalar().orElseThrow();
        return fromPrivateKey(rawPrivateKey);
    }

    public static XECKeyPair fromPrivateKey(byte[] rawPrivateKey) {
        if (rawPrivateKey.length != 32) {
            throw new RuntimeException("Private key length must be 32");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            generator.initialize(NamedParameterSpec.X25519, new StaticSecureRandom(rawPrivateKey));
            KeyPair keyPair = generator.genKeyPair();
            return new XECKeyPair((XECPublicKey) keyPair.getPublic(), (XECPrivateKey) keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static XECPublicKey fromU(BigInteger u) {
        try {
            if (u == null) return null;
            return (XECPublicKey) KeyFactory
                    .getInstance("X25519")
                    .generatePublic(
                            new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static XECPrivateKey fromHex(String hex) {
        return fromBytes(DatatypeConverter.parseHexBinary(hex));
    }

    public static XECPrivateKey fromBytes(byte[] bytes) {
        try {
            return (XECPrivateKey) KeyFactory
                    .getInstance("X25519")
                    .generatePrivate(
                            new XECPrivateKeySpec(NamedParameterSpec.X25519, bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
