package soict.it2.groupchat.core.crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;

public class CryptoUtils {

    public static MessageDigest startSHA256() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md;
    }

    public static byte[] hmacSha256(byte[] data, byte[] key) {
        Mac mac;
        byte[] result = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(data);
            result = mac.doFinal();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static byte[] hkdf(byte[] input_keying_material, byte[] salt, byte[] info, int num_bytes) {
        // Extract step
        byte[] pseudo_random_key = hmacSha256(salt, input_keying_material);

        // Expand step
        byte[] output_bytes = new byte[num_bytes];
        byte[] t = new byte[0];
        for (byte i = 0; i < (num_bytes + 31) / 32; i++) {
            byte[] tInput = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, tInput, 0, t.length);
            System.arraycopy(info, 0, tInput, t.length, info.length);
            tInput[tInput.length - 1] = i;

            t = hmacSha256(pseudo_random_key, tInput);
            int num_to_copy = num_bytes - (i * 32);
            if (num_to_copy > 32) {
                num_to_copy = 32;
            }

            System.arraycopy(t, 0, output_bytes, i * 32, num_to_copy);
        }
        return output_bytes;
    }

    public static byte[] randomBytes(int n) {
        byte[] result = new byte[n];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(result);
        return result;
    }

    public static byte[] encrypt(byte[] message, byte[] keyBytes) {
        Cipher cipher;
        Key key;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] nonce = randomBytes(12);
            GCMParameterSpec paramSpec = new GCMParameterSpec(16 * 8, nonce);

            key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

            int len = cipher.getOutputSize(message.length);
            byte[] result = new byte[len + 12];
            System.arraycopy(nonce, 0, result, 0, 12);

            cipher.doFinal(
                    message,
                    0,
                    message.length,
                    result,
                    12
            );
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] encrypted, byte[] keyBytes) {
        Cipher cipher;
        Key key;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");

            byte[] nonce = Arrays.copyOfRange(encrypted, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(encrypted, 12, encrypted.length);
            GCMParameterSpec paramSpec = new GCMParameterSpec(16 * 8, nonce);

            key = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static XECKeyPair setupExchangeKey(
            XECKeyPair adminIdKeys,
            XECPublicKey memberIdKey,
            XECKeyPair setupKeys,
            XECPublicKey memberEphemeralKey
    ) {
        MessageDigest md = startSHA256();
        md.update(X25519Utils.exchange(adminIdKeys, memberIdKey));
        md.update(X25519Utils.exchange(adminIdKeys, memberEphemeralKey));
        md.update(X25519Utils.exchange(setupKeys, memberIdKey));
        md.update(X25519Utils.exchange(setupKeys, memberEphemeralKey));
        byte[] raw = md.digest();
        return X25519Utils.fromPrivateKey(raw);
    }

    public static XECKeyPair recomputeExchangeKey(
            XECKeyPair selfIdKeys,
            XECPublicKey adminIdKey,
            XECKeyPair selfEphemeralKeys,
            XECPublicKey setupKey
    ) {
        MessageDigest md = startSHA256();
        md.update(X25519Utils.exchange(selfIdKeys, adminIdKey));
        md.update(X25519Utils.exchange(selfEphemeralKeys, adminIdKey));
        md.update(X25519Utils.exchange(selfIdKeys, setupKey));
        md.update(X25519Utils.exchange(selfEphemeralKeys, setupKey));
        byte[] raw = md.digest();
        return X25519Utils.fromPrivateKey(raw);
    }

}
