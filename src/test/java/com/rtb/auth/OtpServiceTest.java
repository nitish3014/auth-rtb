package com.rtb.auth;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.rtb.auth.component.Cypher;
import com.rtb.core.entity.user.Otp;
import com.rtb.auth.enums.NotificationChannel;
import com.rtb.auth.service.OtpService;
import com.rtb.auth.service.WebClientService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rtb.core.repository.OtpRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OtpServiceTest {

  @Mock
  private ObjectMapper objectMapper;
  @Mock
  private Cypher cypher;
  @Mock
  private OtpRepository otpRepository;

  @Mock
  private WebClientService webClientService;

  @Spy
  // Make this a Spy instead of InjectMocks
  @InjectMocks
  private OtpService otpService;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    // Spy the actual service after mocks are initialized
    otpService = spy(new OtpService(objectMapper, cypher, otpRepository,
            webClientService));
  }

  @Test
  void testSendOtp() throws Exception {
    // Arrange
    Map<String, Object> payload = new HashMap<>();
    payload.put("key", "value");
    String fakeEncryptedPayload = "fakeEncryptedPayload";

    // Mock the createValidationPayload method to return a fake encrypted payload
    doReturn(fakeEncryptedPayload)
      .when(otpService).createValidationPayload(anyMap(), any(), anyString());

    // Continue with your test setup
    Otp otp = new Otp(fakeEncryptedPayload, "123456");
    otp.setId("1");
    when(otpRepository.save(any(Otp.class))).thenReturn(otp);

    // Act
    String id = otpService.send(payload, NotificationChannel.SMS, "1234567890");

    // Assert
    assertNotNull(id);
    // Verify this method is called
    verify(otpService).createValidationPayload(anyMap(), any(), anyString());
    verify(otpRepository).save(any(Otp.class));
  }
  @Test
  void testValidateOtpValid() throws Exception {
    // Arrange
    String encryptedPayload = "encryptedPayload";
    String otpValue = "123456";
    String validationId = "1";

    Otp otp = new Otp(encryptedPayload, otpValue);
    otp.setUsed(false);
    otp.setCreatedAt(LocalDateTime.now().minusMinutes(5)); // Ensure OTP is not expired

    when(otpRepository.findByValidationPayload(validationId)).thenReturn(Optional.of(otp));
    when(cypher.decrypt(encryptedPayload)).thenReturn("{\"userId\":1}");

    // Configure ObjectMapper to simulate JSON parsing that fits the expected structure
    JsonNode jsonNode = mock(JsonNode.class);
    when(jsonNode.has("userId")).thenReturn(true);
    when(jsonNode.get("userId")).thenReturn(jsonNode);
    when(jsonNode.asLong()).thenReturn(1L);
    when(objectMapper.readTree(anyString())).thenReturn(jsonNode);

    // Act
    Optional<Long> result = otpService.validate(otpValue, validationId);

    // Assert
    assertTrue(result.isPresent(), "Expected result to be present");
    assertEquals(1L, result.get().longValue(), "Expected User ID to match");

    // Verify interactions
    verify(otpRepository).findByValidationPayload(validationId);
    verify(cypher).decrypt(encryptedPayload);
    verify(objectMapper).readTree(anyString());
    verify(otpRepository).save(otp); // Verify that the OTP was marked as used
  }

}
