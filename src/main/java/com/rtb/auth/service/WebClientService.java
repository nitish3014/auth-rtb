package com.rtb.auth.service;


import com.rtb.auth.dto.CommunicationRequest;
import com.rtb.auth.dto.KafkaProduceEventDto;
import com.rtb.core.entity.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rtb.core.enums.CommunicationCategory;
import com.rtb.core.enums.CommunicationChannel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class WebClientService {
    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    public WebClientService(
            WebClient.Builder webClientBuilder,
            @Value("${url.message_bus_service}") String messageBaseURL,
            ObjectMapper objectMapper
    ) {
        this.webClient = webClientBuilder.baseUrl(messageBaseURL).build();
        this.objectMapper = objectMapper;
    }

    public void sendOtpEmail(User user, String otp) {
        CommunicationRequest request = new CommunicationRequest();
        request.setChannel(CommunicationChannel.EMAIL.toString());
        request.setUserId(user.getId());
        request.setTenantId(user.getTenantId());

        Map<String, Object> requestPayload = new HashMap<>();
        requestPayload.put("data", Map.of(
                "otp", otp,
                "userName", user.getUsername()
        ));
        requestPayload.put("category", CommunicationCategory.OTP_VERIFICATION.toString());
        requestPayload.put("subject", "Resend OTP for account verification");

        request.setPayload(requestPayload);

        KafkaProduceEventDto kafkaProduceEventDto = KafkaProduceEventDto.builder()
                .eventname(AppConstants.COMMUNICATION_EVENT)
                .origin(AppConstants.ENTITY_ID)
                .timestamp(System.currentTimeMillis())
                .payload(objectMapper.valueToTree(request))
                .build();


        webClient.post()
                .uri("/api/v1/messagebus/event/1")
                .bodyValue(objectMapper.convertValue(kafkaProduceEventDto, Map.class))
                .retrieve()
                .bodyToMono(Void.class)
                .doOnNext(response -> log.info("OTP Resent Successfully: {}", response))
                .doOnError(error -> log.error("Error Resending OTP: {}", error.getMessage()))
                .subscribe();


    }
}
