package com.rtb.auth.dto.response;

public class OtpVerificationResponse {
  private boolean success;
  private String message;

  // Constructor
  public OtpVerificationResponse(boolean success, String message) {
    this.success = success;
    this.message = message;
  }

  // Getters
  public boolean isSuccess() {
    return success;
  }

  public String getMessage() {
    return message;
  }

  // Static factory methods for convenience
  public static OtpVerificationResponse success(String message) {
    return new OtpVerificationResponse(true, message);
  }

  public static OtpVerificationResponse failure(String message) {
    return new OtpVerificationResponse(false, message);
  }
}
