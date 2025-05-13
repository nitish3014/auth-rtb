package com.rtb.auth.enums;

import java.util.stream.Stream;

public enum RoleType {

  ADMIN("admin"),
  USER("user"),
  SUPER_ADMIN("super_admin"),
  DEFAULT_ROLE("end user");  // Handling unknown roles gracefully

  private final String value;

  RoleType(String value) {
    this.value = value;
  }

  public static RoleType of(String value) {
    return Stream.of(RoleType.values())
      .filter(v -> v.getValue().equalsIgnoreCase(value))
      .findFirst()
      .orElse(DEFAULT_ROLE);  // Return default if no match is found
  }

  public String getValue() {
    return value;
  }
}