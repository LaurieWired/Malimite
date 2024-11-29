package com.lauriewired.malimite.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class KeyEncryption {
    private static final String ALGORITHM = "AES";
    private static final String SECRET = "MALIMITE_" + System.getProperty("user.name");
    private static final byte[] SALT = "MALIMITE_SALT_123".getBytes();
    
    private static SecretKey generateKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(SECRET.toCharArray(), SALT, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
    }
    
    public static String encrypt(String value) {
        try {
            if (value == null || value.isEmpty()) return "";
            
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting value", e);
        }
    }
    
    public static String decrypt(String encrypted) {
        try {
            if (encrypted == null || encrypted.isEmpty()) return "";
            
            SecretKey key = generateKey();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting value", e);
        }
    }
} 