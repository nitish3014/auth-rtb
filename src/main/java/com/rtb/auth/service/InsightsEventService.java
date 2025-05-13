package com.rtb.auth.service;

import com.rtb.auth.dto.KafkaProduceEventDto;
import com.rtb.auth.util.EventNames;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Map;

@Service
@Slf4j
public class InsightsEventService {
    @Autowired
    private UUIDService uuidService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private HttpRequestService httpRequestService;

    private final String messageBaseURL;

    public InsightsEventService(@Value("${url.message_bus_service}") String messageBaseURL) {
        this.messageBaseURL = messageBaseURL;
    }

    @Async
    public void sendEvents(Long eventId, Object data, String message, Boolean status,
                           Integer httpStatusCode, Long tenantId, Long userId) {

        ObjectNode objectNodeData = objectMapper.convertValue(data, ObjectNode.class);
        if (objectNodeData == null) {
            objectNodeData = objectMapper.createObjectNode();
        }

        if (objectNodeData.get("insightsDataFrontend") == null) {
            objectNodeData.put("insightsDataFrontend", objectMapper.createObjectNode());
        }

        // check if tenantId is null
        if (tenantId == null) {
            tenantId = 0L;
        }

        KafkaProduceEventDto kafkaProduceEventDto = getParsedKafkaProduceEventDto(eventId,
                objectNodeData, message, status, httpStatusCode, tenantId, userId);

        sendDataToKafka(kafkaProduceEventDto, tenantId);
    }

    private KafkaProduceEventDto getParsedKafkaProduceEventDto(
            Long eventId, ObjectNode data,
             String message, Boolean status, Integer httpStatusCode,
             Long tenantId, Long userId) {

        ObjectNode extendedPayload = objectMapper.createObjectNode();
        extendedPayload.put("IP", data.get("insightsDataFrontend").get("ipAddress"));
        extendedPayload.put("Location", data.get("insightsDataFrontend").get("location"));
        extendedPayload.put("Timezone", data.get("insightsDataFrontend").get("timeZone"));
        extendedPayload.put("Status", status);
        extendedPayload.put("HttpStatusCode", httpStatusCode);
        extendedPayload.put("Message", message);
        extendedPayload.put("AndroidId", data.get("insightsDataFrontend").get("androidId"));
        extendedPayload.put("AppleId", data.get("insightsDataFrontend").get("appleId"));
        extendedPayload.put("DeviceBrand", data.get("insightsDataFrontend").get("deviceBrand"));
        extendedPayload.put("DeviceModel", data.get("insightsDataFrontend").get("deviceModel"));
        extendedPayload.put("AppVersion", data.get("insightsDataFrontend").get("appVersion"));
        extendedPayload.put("NetworkProvider",
                data.get("insightsDataFrontend").get("networkProvider"));

        if (data.get("email") != null) {
            extendedPayload.put("Email", data.get("email").asText());
        }

        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("RecordId", uuidService.generateRandomUUID());
        payload.put("EventId", eventId);
        payload.put("EventName", EventNames.getEventName(eventId));
        payload.put("EntityType", AppConstants.ENTITY_TYPE);
        payload.put("OSVersion", data.get("insightsDataFrontend").get("osVersion"));
        payload.put("EntityId", AppConstants.ENTITY_ID);
        payload.put("EventTimestamp", System.currentTimeMillis());
        payload.put("UserId", userId);
        payload.put("TenantId", tenantId);
        payload.set("ExtendedPayload", extendedPayload);

        return KafkaProduceEventDto.builder()
                .eventname(AppConstants.ENTITY_NAME)
                .origin(AppConstants.ENTITY_ID)
                .timestamp(System.currentTimeMillis())
                .payload(payload)
                .build();
    }

    private void sendDataToKafka(KafkaProduceEventDto kafkaProduceEventDto, Long tenantId) {
        // Send data to kafka
        Map<String, Object> reqBody = objectMapper.convertValue(kafkaProduceEventDto, Map.class);
        try {
            httpRequestService.sendPostRequestWithoutReturn(messageBaseURL
                    + "/api/v1/messagebus/event/1", reqBody);
        } catch (IOException | InterruptedException e) {
            log.error("Error sending data to kafka", e);
        }
    }
}
