package com.rtb.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@AllArgsConstructor
public class GoogleLoginDto {

    private InsightsFrontendDto insightsDataFrontend;

    @NotEmpty(message = "Display is Required")
    private String displayName;

    @NotEmpty(message = "Display is Required")
    @Email(message = "Email not Valid")
    private String email;

    @NotEmpty(message = "ID is Required")
    private String id;

    private String photoUrl;

    @NotEmpty(message = "Token is Required")
    private String token;

    @NotEmpty(message = "Device Type is Required")
    private String deviceType;
}
