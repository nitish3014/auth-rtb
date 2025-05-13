package com.rtb.auth.enums;

import java.util.stream.Stream;

public enum LoginMethod {

  BASIC_EMAIL_PASSWORD("basic#email.password"),
  PASSWORDLESS_EMAIL("password_less#email"),
  PASSWORDLESS_PHONE("password_less#phone");

  private final String value;

  LoginMethod(String value) {
    this.value = value;
  }

  public static LoginMethod of(String value) {
    return Stream.of(LoginMethod.values()).filter(v -> v.getValue().equals(value)).findFirst()
        .orElseThrow(IllegalArgumentException::new);
  }

  public String getValue() {
    return value;
  }

}
