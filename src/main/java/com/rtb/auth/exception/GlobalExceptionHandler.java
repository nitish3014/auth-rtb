package com.rtb.auth.exception;

import com.rtb.auth.payload.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(BadRequestException.class)
  public ResponseEntity<String> badRequestExceptionHandler(BadRequestException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
  }

  @ExceptionHandler(InvalidCredentialException.class)
  public ResponseEntity<ApiResponse> invalidCredentialsHandler(InvalidCredentialException ex) {

    ApiResponse response = ApiResponse.builder()
      .message(ex.getMessage())
      .error(HttpStatus.valueOf(401))
      .build();

    return ResponseEntity.status(HttpStatus.valueOf(401)).body(response);

  }

  @ExceptionHandler(TooManyAttemptsException.class)
  @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
  public Map<String, String> handleTooManyAttemptsException(TooManyAttemptsException ex) {
    Map<String, String> errorResponse = new HashMap<>();
    errorResponse.put("error", "Too Many Requests");
    errorResponse.put("message", ex.getMessage());
    return errorResponse;
  }
}
