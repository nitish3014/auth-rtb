package com.rtb.auth.dto.response;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ErrorResponse {
    private String response;
    private String error;

    public ErrorResponse(String response, String error) {
        this.response = response;
        this.error = error;
    }
}
