package com.rtb.auth.dto;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class KafkaProduceEventDto {

    private String eventname;

    // Originating service for this event
    private String origin;

    // Timestamp when this event was created
    private long timestamp;

    // The event payload, always a dto
    private JsonNode payload;
}