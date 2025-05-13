package com.rtb.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {


  private final String tokenType = "Bearer";

  private String accessToken;

  private List<String> roles;

  private Set<String> permissions;

  private String primaryColor = "#00B6B1";

  private String secondaryColor = "#575252";

  private String logo;

  private Long userId;

  private String userName;

  private String message;


}
