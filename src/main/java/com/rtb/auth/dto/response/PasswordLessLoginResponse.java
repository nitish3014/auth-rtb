package com.rtb.auth.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PasswordLessLoginResponse {

  private String validationId;

}
