package com.rtb.auth.service;

import com.rtb.core.entity.user.User;
import com.rtb.auth.exception.OTPCreationException;
import com.rtb.auth.component.Cypher;
import com.rtb.core.entity.user.Otp;
import com.rtb.auth.enums.NotificationChannel;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rtb.core.enums.OTPAction;
import com.rtb.core.repository.OtpRepository;
import lombok.Data;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class OtpService {

  private static final int OTP_LENGTH = 6;

  // Otp expiry time in minutes
  private static final int OTP_EXPIRY_TIMER = 1000000000;

  private final ObjectMapper objectMapper;

  private final Cypher cypher;

  private final OtpRepository otpRepository;

  private final WebClientService webClientService;

  public OtpService(ObjectMapper objectMapper, Cypher cypher, OtpRepository otpRepository,
                    WebClientService webClientService) {
    this.objectMapper = objectMapper;
    this.cypher = cypher;
    this.otpRepository = otpRepository;
    this.webClientService = webClientService;
  }

  public String send(Map<String, Object> payload, NotificationChannel channel,
                     String channelAddress) {
    String validationPayload = createValidationPayload(payload, channel, channelAddress);
    Otp otp = new Otp(validationPayload, generateOtpValue());
    otp = otpRepository.save(otp);

    // INFO: Send otp via kafka, for now just logging
    log.info("Sent otp {} via {} to {}", otp.getValue(), channel, channelAddress, otp.getId());
    return otp.getId();
  }


  public Optional<Long> validate(String value, String validationId) {
    Otp otp = otpRepository.findByValidationPayload(validationId).orElse(null);

    if (otp == null || !otp.getValue().equals(value) || otp.isUsed() || isOtpExpired(otp)) {
      return Optional.empty();
    }

    try {
      String decryptedPayload = cypher.decrypt(otp.getValidationPayload());
      JsonNode payloadNode = objectMapper.readTree(decryptedPayload);

      // Navigate to the 'data' node first
      JsonNode dataNode = payloadNode.get("data");
      if (payloadNode.has("userId")) {
        Long userId = payloadNode.get("userId").asLong();
        System.out.println("Extracted User ID: " + userId);

        // Your subsequent logic to mark OTP as used and update database etc.
        otp.setUsed(true);
        otpRepository.save(otp);
        return Optional.of(userId);  // assuming you return Optional<Long> from your method
      } else {
        return Optional.empty();
      }
    } catch (JsonProcessingException e) {
      log.error("Error in processing validation payload", e);
      return Optional.empty();
    }

  }

  public Optional<Long> verify(String value, String validationId) {
    Otp otp = otpRepository.findByValidationPayload(validationId).orElse(null);

    if (otp == null || !otp.getValue().equals(value) || otp.isUsed() || isOtpExpired(otp)) {
      return Optional.empty();
    }

    try {
      String decryptedPayload = cypher.decrypt(otp.getValidationPayload());
      JsonNode payloadNode = objectMapper.readTree(decryptedPayload);

      JsonNode dataNode = payloadNode.get("data");
      if (payloadNode.has("userId")) {
        Long userId = payloadNode.get("userId").asLong();
        System.out.println("Extracted User ID: " + userId);

        return Optional.of(userId);
      } else {
        return Optional.empty();
      }
    } catch (JsonProcessingException e) {
      log.error("Error in processing validation payload", e);
      return Optional.empty();
    }

  }

  @SneakyThrows
  public String createValidationPayload(Map<String, Object> payload, NotificationChannel channel,
                                        String channelAddress) {
    ValidationPayload validationPayload = new ValidationPayload();
    validationPayload.setTimestamp(LocalDateTime.now());
    validationPayload.setChannel(channel);
    validationPayload.setChannelAddress(channelAddress);
    validationPayload.setData(payload);

    return cypher.encrypt(objectMapper.writeValueAsString(validationPayload));
  }

  public Otp generateOtp(User user, OTPAction action) {

    try {
      Map<String, Object> payload = new HashMap<>();
      payload.put("userId", user.getId());
      payload.put("action", action);

      String otpValue;
      String validationPayload;

      validationPayload = cypher.encrypt(objectMapper.writeValueAsString(payload));
      otpValue = generateOtpValue();

      Otp otp = new Otp(validationPayload, otpValue);
      otp = otpRepository.save(otp);

      webClientService.sendOtpEmail(user, otp.getValue());
      return otp;

    } catch (Exception e) {
      throw new OTPCreationException("Exception while generation an OTP");
    }

  }

  private String generateOtpValue() {
    String characters = "0123456789";
    SecureRandom random = new SecureRandom();
    StringBuilder otp = new StringBuilder(OTP_LENGTH);

    for (int i = 0; i < OTP_LENGTH; i++) {
      int randomIndex = random.nextInt(characters.length());
      otp.append(characters.charAt(randomIndex));
    }

    return otp.toString();
  }

  private boolean isOtpExpired(Otp otp) {
    long diff = Duration.between(otp.getCreatedAt(), LocalDateTime.now()).toMinutes();
    return diff > OTP_EXPIRY_TIMER;
  }

  @Data
  static class ValidationPayload {
    @Getter private Long userId;

    private LocalDateTime timestamp;

    private NotificationChannel channel;

    private String channelAddress;

    private Map<String, Object> data;
  }

}
