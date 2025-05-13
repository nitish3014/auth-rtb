package com.rtb.auth.service;

public class AppConstants {

    private AppConstants() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static final String TOKEN_URL = "https://appleid.apple.com/auth/token";
    public static final String FACEBOOK_JWKS_URI =
            "https://www.facebook.com/.well-known/oauth/openid/jwks/?_rdr";
    public static final String ENTITY_TYPE = "3";
    public static final String ENTITY_ID = "auth-service";
    public static final String ENTITY_NAME = "insights-event";
    public static final String COMMUNICATION_EVENT = "communication-event";
}
