package com.rtb.auth.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
public class CommunicationRequest {
    private Long tenantId;
    private Long userId;
    private String channel;
    private Map<String, Object> payload;
}
