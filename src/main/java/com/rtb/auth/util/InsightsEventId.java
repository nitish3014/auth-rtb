package com.rtb.auth.util;

public final class InsightsEventId {
    private InsightsEventId() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static final Long EMAIL_LOGIN_RECEIVED = 9002L;
    public static final Long EMAIL_LOGIN_SUCCESS = 9003L;
    public static final Long FAILED_TO_LOGIN = 9004L;

    public static final Long GOOGLE_LOGIN_RECEIVED = 9006L;
    public static final Long GOOGLE_LOGIN_FAILED = 9007L;
    public static final Long GOOGLE_LOGIN_SUCCESS = 9008L;

    public static final Long FACEBOOK_LOGIN_RECEIVED = 9010L;
    public static final Long FACEBOOK_LOGIN_FAILED = 9011L;
    public static final Long FACEBOOK_LOGIN_SUCCESS = 9012L;

    public static final Long OTP_VERIFICATION_RECEIVED = 9014L;
    public static final Long OTP_VERIFICATION_FAILED = 9015L;
    public static final Long OTP_VERIFICATION_SUCCESS = 9016L;

    public static final Long APPLE_LOGIN_RECEIVED = 9018L;
    public static final Long APPLE_LOGIN_FAILED = 9019L;
    public static final Long APPLE_LOGIN_SUCCESS = 9020L;

    public static final Long OTP_FAILURE = 9021L;
    public static final Long FAILED_TO_SEND_OTP = 9022L;





}
