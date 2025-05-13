package com.rtb.auth.util;

public class CommonUtil {

  protected CommonUtil() {

  }

  /**
   * Removes all non digit elements from a phone number.
   */
  public static String sanitizePhone(String phone) {
    return phone.replaceAll("[^0-9]", "");
  }

}
