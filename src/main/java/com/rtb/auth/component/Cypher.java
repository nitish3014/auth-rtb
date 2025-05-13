package com.rtb.auth.component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class Cypher {

  private static final String BLOCK_CIPHER = "AES/GCM/NoPadding";
  private static final int AUTH_TAG_BYTE_LENGTH = 128;
  private static final int IV_BYTE_LENGTH = 12;

  @Value("${cypher.key}")
  private String encryptionKey;

  private byte[] getIv() {
    byte[] randomBytes = new byte[IV_BYTE_LENGTH];
    new SecureRandom().nextBytes(randomBytes);
    return randomBytes;
  }

  public String encrypt(String value) {
    try {
      byte[] iv = getIv();

      Cipher cipher = Cipher.getInstance(BLOCK_CIPHER);
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTH_TAG_BYTE_LENGTH, iv);
      cipher.init(Cipher.ENCRYPT_MODE, generateKey(encryptionKey), gcmParameterSpec);

      byte[] encryptedMsg = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));

      byte[] encryptedMsgBuffer = new byte[iv.length + encryptedMsg.length];
      System.arraycopy(iv, 0, encryptedMsgBuffer, 0, iv.length);
      System.arraycopy(encryptedMsg, 0, encryptedMsgBuffer, iv.length, encryptedMsg.length);

      return Base64.getEncoder().encodeToString(encryptedMsgBuffer);
    } catch (Exception e) {
      log.error("Error during encryption", e);
      return null;
    }
  }

  public String decrypt(String encryptedValue) {
    try {
      byte[] encryptedMsgBuffer = Base64.getDecoder().decode(encryptedValue);

      byte[] iv = new byte[IV_BYTE_LENGTH];
      System.arraycopy(encryptedMsgBuffer, 0, iv, 0, IV_BYTE_LENGTH);

      Cipher cipher = Cipher.getInstance(BLOCK_CIPHER);
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTH_TAG_BYTE_LENGTH, iv);
      cipher.init(Cipher.DECRYPT_MODE, generateKey(encryptionKey), gcmParameterSpec);

      byte[] encryptedMessage = new byte[encryptedMsgBuffer.length - iv.length];
      System.arraycopy(encryptedMsgBuffer, iv.length, encryptedMessage, 0,
          encryptedMessage.length);

      byte[] decryptedValue = cipher.doFinal(encryptedMessage);

      return new String(decryptedValue, StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.error("Error during decryption", e);
      return null;
    }
  }

  private SecretKeySpec generateKey(String key) throws Exception {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    keyBytes = sha.digest(keyBytes);
    return new SecretKeySpec(keyBytes, "AES");
  }

}
