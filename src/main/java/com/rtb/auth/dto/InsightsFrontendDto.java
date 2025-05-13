package com.rtb.auth.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class InsightsFrontendDto {
    private String osVersion;
    private String ipAddress;
    private String location;
    private String timeZone;
    private String androidId;
    private String appleId;
    private String deviceBrand;
    private String deviceModel;
    private String appVersion;
    private String networkProvider;
}
