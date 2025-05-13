package com.rtb.auth.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@AllArgsConstructor
public class AppleLoginDto {

    private InsightsFrontendDto insightsDataFrontend;

    private String firstName;

    private String lastName;

    private String email;

    @NotEmpty(message = "Apple ID is Required")
    private String appleId;

    @NotEmpty(message = "Access Token is Required")
    private String accessToken;
}
