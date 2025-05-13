package com.rtb.auth.controller;

import com.rtb.auth.dto.AppleLoginDto;
import com.rtb.auth.dto.FacebookLoginDto;
import com.rtb.auth.dto.GoogleLoginDto;
import com.rtb.auth.dto.LoginDto;
import com.rtb.auth.dto.RefreshTokenRequestDto;
import com.rtb.auth.dto.RefreshTokenResponseDto;
import com.rtb.auth.dto.VerifyOtpDto;
import com.rtb.auth.dto.ResendOtpDto;
import com.rtb.auth.dto.response.ErrorResponse;
import com.rtb.auth.dto.response.LoginResponse;
import com.rtb.auth.dto.response.LoginResponseMobile;
import com.rtb.auth.dto.response.OtpVerificationResponse;
import com.rtb.auth.exception.BadRequestException;
import com.rtb.auth.exception.ResourceNotFoundException;
import com.rtb.auth.service.AuthService;
import com.rtb.auth.service.OtpVerificationRateLimiter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@Slf4j
public class  AuthController extends BaseController {

  private final AuthService authService;

  private final OtpVerificationRateLimiter otpRateLimiter;

  public AuthController(AuthService authService,
                        OtpVerificationRateLimiter otpRateLimiter) {
    this.authService = authService;
    this.otpRateLimiter = otpRateLimiter;
  }

  @PostMapping("login")
  public ResponseEntity<?> login(
          @Valid @RequestBody LoginDto
                  loginDto, @PathVariable("tenantId") Long tenantId,
          HttpServletResponse response) throws IOException, InterruptedException {

    Object loginResponse = authService.handleLogin(loginDto, tenantId);
    if (loginResponse instanceof LoginResponseMobile) {
        return new ResponseEntity<>(loginResponse, HttpStatus.OK);
    }

    return new ResponseEntity<>(loginResponse, HttpStatus.OK);
  }

  @PostMapping("validate-2f-otp")
  public ResponseEntity<?> validate2fOtp(
          @RequestBody VerifyOtpDto verifyOtpDto,
          HttpServletResponse response
  ) {
    try {
      LoginResponse loginResponseWeb = authService.validate2fOtp(verifyOtpDto);

      Cookie cookie = new Cookie("authToken", loginResponseWeb.getAccessToken());
      cookie.setHttpOnly(true);
      cookie.setPath("/");
      cookie.setMaxAge(60 * 60 * 24);
      cookie.setSecure(true);
      cookie.setAttribute("SameSite", "None");

      response.addCookie(cookie);

      return new ResponseEntity<>(loginResponseWeb, HttpStatus.OK);
    } catch (BadRequestException e) {
      log.error("Bad Request: {}", e.getMessage());
      return new ResponseEntity<>(new ErrorResponse("Bad Request", e.getMessage()) {
      }, HttpStatus.BAD_REQUEST);
    } catch (Exception e) {
      log.error("Unexpected error occurred: {}", e.getMessage());
      return new ResponseEntity<>(new ErrorResponse(
              "Internal Server Error", "An unexpected error occurred"),
              HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @PostMapping("resend-otp")
  public ResponseEntity<String> resendOtp(
          @RequestBody ResendOtpDto resendOtpDto) {
    try {
      String response = authService.resendOtp(resendOtpDto.getValidationId());
      return ResponseEntity.ok(response);
    } catch (UsernameNotFoundException | ResourceNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
    } catch (Exception e) {
      log.error("Error resending OTP: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .body("Failed to resend OTP. Please try again.");
    }
  }



  @PostMapping("google-login")
  public ResponseEntity<?> googleLogin(
          @Valid @RequestBody GoogleLoginDto googleLoginDto,
          @PathVariable("tenantId") Long tenantId
  ) {
    return new ResponseEntity<>(
            authService.handleGoogleLogin(googleLoginDto, tenantId), HttpStatus.OK
    );
  }

  @PostMapping("facebook-login")
  public ResponseEntity<?> facebookLogin(
          @Valid @RequestBody FacebookLoginDto facebookLoginDto,
          @PathVariable("tenantId") Long tenantId
  ) {
    return new ResponseEntity<>(
            authService.handleFacebookLogin(facebookLoginDto, tenantId), HttpStatus.OK
    );
  }

  @PostMapping("apple-login")
  public ResponseEntity<?> appleLogin(
          @Valid @RequestBody AppleLoginDto appleLoginDto,
          @PathVariable("tenantId") Long tenantId
  ) {
      return new ResponseEntity<>(
              authService.handleAppleLogin(appleLoginDto, tenantId), HttpStatus.OK
      );
  }

  @PostMapping("refresh-token")
  public ResponseEntity<RefreshTokenResponseDto> refreshToken(
          @Valid @RequestBody RefreshTokenRequestDto requestDto,
          @PathVariable("tenantId") Long tenantId
  ) {
      return authService.handleRefreshToken(requestDto, tenantId);
  }

  @PostMapping("register/verify-otp")
  public ResponseEntity<String> verifyOtp(
          @Validated @RequestBody VerifyOtpDto verifyOtpDto,
          @PathVariable("tenantId") Long tenantId,
          HttpServletRequest request
  ) {
    String ip = request.getRemoteAddr();
    String validationId = verifyOtpDto.getValidationId();

    if (otpRateLimiter.isBlocked(validationId, ip)) {
      return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
              .body("Too many OTP attempts. Please try again later.");
    }

    otpRateLimiter.recordAttempt(validationId, ip);

    OtpVerificationResponse response = authService.verifyOtpAndSetUserVerified(
      verifyOtpDto.getOtp(), verifyOtpDto.getValidationId(), tenantId);

    if (!response.isSuccess()) {
      Map<String, String> errorResponse = new HashMap<>();
      errorResponse.put("message", response.getMessage());
      errorResponse.put("status", "failed");

      return ResponseEntity
              .status(HttpStatus.BAD_REQUEST).body(errorResponse.toString());
    }

    otpRateLimiter.resetAttempts(validationId, ip);

    return ResponseEntity.ok(response.getMessage());
  }

  @PostMapping("forgot-password/verify-otp")
  public ResponseEntity<String> verifyForgotPasswordOtp(
          @Validated @RequestBody VerifyOtpDto verifyOtpDto,
          @PathVariable("tenantId") Long tenantId
  ) {
      OtpVerificationResponse response = authService.verifyForgotPasswordOtp(
      verifyOtpDto.getOtp(), verifyOtpDto.getValidationId(), tenantId);

      if (!response.isSuccess()) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response.getMessage());
      }

      return ResponseEntity.ok(response.getMessage());
  }
}
