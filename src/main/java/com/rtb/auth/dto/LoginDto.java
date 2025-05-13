package com.rtb.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginDto {

  private InsightsFrontendDto insightsDataFrontend;

  @NotEmpty(message = "Email is required")
  @Email(message = "Invalid email")
  private String email;

  @NotEmpty(message = "Password is required")
  @Size(min = 8, max = 64, message = "Password should be 8 - 64 characters")
  private String password;

}
