package com.rtb.auth.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class VerifyOtpDto {

  private InsightsFrontendDto insightsDataFrontend;

  @NotEmpty(message = "Otp is required")
  @Size(min = 6, max = 6, message = "Otp should be 6 digits")
  private String otp;

  @NotEmpty(message = "Validation id is missing")
  private String validationId;





}
