package com.rtb.auth.enums;

import java.util.stream.Stream;

public enum NotificationChannel {

  EMAIL("email"),
  SMS("sms"),
  PUSH("push_notification"),
  PUSH_PWA("push_pwa"),
  WHATSAPP("whatsapp");

  private final String value;

  NotificationChannel(String value) {
    this.value = value;
  }

  public static NotificationChannel of(String value) {
    return Stream.of(NotificationChannel.values()).filter(v -> v.getValue().equals(value))
        .findFirst().orElseThrow(IllegalArgumentException::new);
  }

  public String getValue() {
    return value;
  }

}
