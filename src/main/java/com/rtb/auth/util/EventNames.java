package com.rtb.auth.util;

import java.util.HashMap;
import java.util.Map;

public final class EventNames {

    private EventNames() {}

    private static final Map<Long, String> EVENT_NAME_MAP = new HashMap<>();

    static {
        EVENT_NAME_MAP.put(9001L, "Email Login - Initiated");
        EVENT_NAME_MAP.put(9002L, "Email Login - Request Received");
        EVENT_NAME_MAP.put(9003L, "Email Login - Success");
        EVENT_NAME_MAP.put(9004L, "Email Login - Failed");

        EVENT_NAME_MAP.put(9005L, "Google Login - Initiated");
        EVENT_NAME_MAP.put(9006L, "Google Login - Request Received");
        EVENT_NAME_MAP.put(9007L, "Google Login - Failed");
        EVENT_NAME_MAP.put(9008L, "Google Login - Success");

        EVENT_NAME_MAP.put(9009L, "Facebook Login - Initiated");
        EVENT_NAME_MAP.put(9010L, "Facebook Login - Request Received");
        EVENT_NAME_MAP.put(9011L, "Facebook Login - Failed");
        EVENT_NAME_MAP.put(9012L, "Facebook Login - Success");

        EVENT_NAME_MAP.put(9013L, "OTP Verification - Initiated");
        EVENT_NAME_MAP.put(9014L, "OTP Verification - Request Received");
        EVENT_NAME_MAP.put(9015L, "OTP Verification - Failed");
        EVENT_NAME_MAP.put(9016L, "OTP Verification - Success");

        EVENT_NAME_MAP.put(9017L, "Apple Login - Initiated");
        EVENT_NAME_MAP.put(9018L, "Apple Login - Request Received");
        EVENT_NAME_MAP.put(9019L, "Apple Login - Failed");
        EVENT_NAME_MAP.put(9020L, "Apple Login - Success");
    }

    public static String getEventName(Long eventId) {
        return EVENT_NAME_MAP.getOrDefault(eventId, "Unknown Event");
    }
}
