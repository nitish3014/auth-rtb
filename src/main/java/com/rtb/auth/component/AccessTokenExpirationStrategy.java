package com.rtb.auth.component;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AccessTokenExpirationStrategy {

  @Getter
  @Value("${auth.hotel-admin-access-token-expiry}")
  private int hotelAdminAccessTokenExpiry;

  @Getter
  @Value("${auth.hotel-bellboy-access-token-expiry}")
  private int hotelBellboyAccessTokenExpiry;

}
