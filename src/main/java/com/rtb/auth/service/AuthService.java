package com.rtb.auth.service;

import com.rtb.auth.component.AccessTokenExpirationStrategy;
import com.rtb.auth.component.Cypher;
import com.rtb.auth.dto.AppleLoginDto;
import com.rtb.auth.dto.CommunicationRequest;
import com.rtb.auth.dto.FacebookLoginDto;
import com.rtb.auth.dto.FeatureDTO;
import com.rtb.auth.dto.FeatureResponseDto;
import com.rtb.auth.dto.LoginDto;
import com.rtb.auth.dto.GoogleLoginDto;
import com.rtb.auth.dto.RefreshTokenRequestDto;
import com.rtb.auth.dto.VerifyOtpDto;
import com.rtb.auth.dto.KafkaProduceEventDto;
import com.rtb.auth.dto.RefreshTokenResponseDto;
import com.rtb.auth.dto.response.LoginResponse;
import com.rtb.auth.dto.response.LoginResponseMobile;
import com.rtb.auth.dto.response.OtpVerificationResponse;
import com.rtb.auth.enums.RoleType;
import com.rtb.core.entity.auth.RefreshToken;
import com.rtb.core.entity.user.FeatureProduct;
import com.rtb.core.entity.user.User;
import com.rtb.core.entity.user.Subscription;
import com.rtb.core.entity.user.UserSubscription;
import com.rtb.core.entity.tenant.Feature;
import com.rtb.core.entity.tenant.FeaturePermission;
import com.rtb.core.entity.user.Role;
import com.rtb.core.entity.user.Permission;
import com.rtb.core.entity.user.Otp;
import com.rtb.core.entity.tenant.Tenant;
import com.rtb.auth.exception.InvalidCredentialException;
import com.rtb.auth.exception.SubscriptionNotFoundException;
import com.rtb.auth.exception.BadRequestException;
import com.rtb.auth.exception.UserNotFoundException;
import com.rtb.core.enums.CommunicationCategory;
import com.rtb.core.enums.CommunicationChannel;
import com.rtb.core.enums.OTPAction;
import com.rtb.core.enums.SubscriptionType;
import com.rtb.core.repository.FeaturePermissionRepository;
import com.rtb.core.repository.FeatureProductRepository;
import com.rtb.core.repository.FeatureRepository;
import com.rtb.core.repository.OtpRepository;
import com.rtb.core.repository.RefreshTokenRepository;
import com.rtb.auth.exception.TooManyAttemptsException;
import com.rtb.core.repository.RoleRepository;
import com.rtb.core.repository.SubscriptionRepository;
import com.rtb.core.repository.TenantRepository;
import com.rtb.core.repository.UserSubscriptionRepository;
import com.rtb.auth.util.InsightsEventId;
import com.rtb.auth.util.Messages;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rtb.core.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthService {

    private final UserService userService;
    private final AccessTokenExpirationStrategy accessTokenExpirationStrategy;
    private final OtpService otpService;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final HttpRequestService httpRequestService;
    private final JWTDecodeAndVerificationService
            jwtDecodeAndVerificationService;
    private final InsightsEventService insightsEventService;
    private final RoleRepository roleRepository;
    private final SubscriptionRepository subscriptionRepository;
    private final UserSubscriptionRepository userSubscriptionRepository;
    private final TenantRepository tenantRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RateLimiterService rateLimiterService;
    private final String messageBaseUrl;
    private final String defaultOtp;
    private final boolean enableDefaultOtp;
    private final FeatureRepository featureRepository;
    private final FeaturePermissionRepository featurePermissionRepository;
    private final long tenantAdminRoleId = 34L;
    private final Cypher cypher;
    private final ObjectMapper objectMapper;
    private final OtpRepository otpRepository;
    private final WebClient webClient;
    private final FeatureProductRepository featureProductRepository;
    private final WebClientService webClientService;
    private static final String OTP_LOGIN_ACTION = "LOGIN_ACTION";

    private static final int OTP_LENGTH = 6;

    public AuthService(UserService userService,
                       AccessTokenExpirationStrategy accessTokenExpirationStrategy,
                       OtpService otpService, TokenService tokenService,
                       UserRepository userRepository, HttpRequestService httpRequestService,
                       JWTDecodeAndVerificationService jwtDecodeAndVerificationService,
                       InsightsEventService insightsEventService, RoleRepository roleRepository,
                       SubscriptionRepository subscriptionRepository,
                       UserSubscriptionRepository
                               userSubscriptionRepository,
                       TenantRepository tenantRepository,
                       RateLimiterService rateLimiterService,
                       RefreshTokenRepository refreshTokenRepository,
                       FeatureRepository featureRepository,
                       FeaturePermissionRepository featurePermissionRepository,
                       Cypher cypher,
                       ObjectMapper objectMapper,
                       OtpRepository otpRepository,
                       WebClient.Builder webClientBuilder,
                       WebClientService webClientService,
                       FeatureProductRepository featureProductRepository,
                       @Value("${url.message_bus_service}") String messageBaseURL,
                       @Value("${app.default-otp}") String defaultOtp,
                       @Value("${app.enable-default-otp}") boolean enableDefaultOtp
    ) {
        this.userService = userService;
        this.accessTokenExpirationStrategy = accessTokenExpirationStrategy;
        this.otpService = otpService;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.httpRequestService = httpRequestService;
        this.jwtDecodeAndVerificationService = jwtDecodeAndVerificationService;
        this.insightsEventService = insightsEventService;
        this.roleRepository = roleRepository;
        this.subscriptionRepository = subscriptionRepository;
        this.userSubscriptionRepository = userSubscriptionRepository;
        this.tenantRepository = tenantRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.rateLimiterService = rateLimiterService;
        this.messageBaseUrl = messageBaseURL;
        this.defaultOtp = defaultOtp;
        this.featureRepository = featureRepository;
        this.featurePermissionRepository = featurePermissionRepository;
        this.cypher = cypher;
        this.objectMapper = objectMapper;
        this.otpRepository = otpRepository;
        this.webClient = webClientBuilder.baseUrl(messageBaseURL).build();
        this.webClientService = webClientService;
        this.enableDefaultOtp = enableDefaultOtp;
        this.featureProductRepository = featureProductRepository;
    }

    public Object handleLogin(
            LoginDto loginDto, Long tenantId)
            throws IOException, InterruptedException {

        if (rateLimiterService.isBlocked(loginDto.getEmail())) {
            insightsEventService.sendEvents(
                    InsightsEventId.FAILED_TO_LOGIN, loginDto, Messages.TOO_MANY_ATTEMPTS,
                    false, 429, tenantId, null
            );

            throw new TooManyAttemptsException(Messages.TOO_MANY_ATTEMPTS);
        }

        insightsEventService.sendEvents(InsightsEventId.EMAIL_LOGIN_RECEIVED, loginDto,
                Messages.LOGIN_INITIATED, true, 200, tenantId, null);

        User user =
                userService.getUserByEmail(loginDto.getEmail())
                        .orElseThrow(() -> {
                            insightsEventService.sendEvents(
                                    InsightsEventId.FAILED_TO_LOGIN, loginDto,
                                    Messages.EMAIL_NOT_FOUND,
                                    false, 404, tenantId, null
                            );

                            rateLimiterService.recordLoginAttempt(loginDto.getEmail());

                            return new InvalidCredentialException(
                                    Messages.EMAIL_NOT_FOUND
                            );
                        });

        if (!userService.verifyUserPassword(user, loginDto.getPassword())) {
            insightsEventService.sendEvents(
                    InsightsEventId.FAILED_TO_LOGIN, loginDto, Messages.INCORRECT_PASSWORD,
                    false, 401, tenantId, user.getId()
            );

            rateLimiterService.recordLoginAttempt(loginDto.getEmail());

            throw new InvalidCredentialException(
                    Messages.INCORRECT_PASSWORD
            );
        }

        if (!user.isVerified()) {
            insightsEventService.sendEvents(
                    InsightsEventId.FAILED_TO_LOGIN, loginDto, Messages.VERIFY_EMAIL,
                    false, 401, tenantId, user.getId()
            );

            rateLimiterService.recordLoginAttempt(loginDto.getEmail());

            throw new InvalidCredentialException(
                    Messages.VERIFY_EMAIL);
        }

        List<String> roleNames = user.getRole().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toList());

        if (roleNames.isEmpty()) {
            roleNames = Collections.singletonList(RoleType.DEFAULT_ROLE.getValue());
        }

        Set<String> permissions = user.getRole().stream()
                .flatMap(role -> role.getPermission().stream())
                .map(Permission::getPermissionName)
                .collect(Collectors.toSet());

        boolean isTenantAdmin = user.getRole().stream()
                .anyMatch(role -> role.getId() == tenantAdminRoleId);

        boolean isEndUser = user.getRole().stream()
                .anyMatch(role -> Objects.equals(
                        role.getRoleName(), RoleType.DEFAULT_ROLE.getValue()));

        if (isTenantAdmin) {
            permissions = new HashSet<>(
                    getFeaturesByTenantId(tenantId).getPermissions());
        }

        if (isEndUser) {
            permissions = new HashSet<>(
                    handleEndUserLogin(user.getId()));
        }

        String accessToken = generateAccessToken(
                new AccessTokenClaims(user.getId(), roleNames, user.getTenantId(), permissions),
                accessTokenExpirationStrategy.getHotelAdminAccessTokenExpiry()
        );

        Optional<Tenant> tenant = Optional.ofNullable(user.getTenantId())
                .flatMap(tenantRepository::findById);

        String primaryColor = tenant.<String>map(Tenant::getPrimaryColor)
                .map(String::toUpperCase).orElse("#176d5d");
        String secondaryColor = tenant.<String>map(Tenant::getSecondaryColor)
                .map(String::toUpperCase).orElse("#646363");
        String logoUrl = tenant.<String>map(Tenant::getLogo)
                .orElse("https://portal.mvpin90days.com/assets/logo-light-ypugESCg.png");

        insightsEventService.sendEvents(
                InsightsEventId.EMAIL_LOGIN_SUCCESS, loginDto, Messages.USER_LOGGED_IN_SUCCESSFULLY,
                true, 200, tenantId, user.getId()
        );

        rateLimiterService.resetAttempts(loginDto.getEmail());

        if (roleNames.contains(RoleType.DEFAULT_ROLE.getValue())) {

            String refreshToken = getRefreshToken(user.getId());

            return LoginResponseMobile.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .roles(roleNames)
                    .userName(user.getUsername())
                    .userId(user.getId())
                    .permissions(permissions)
                    .primaryColor(primaryColor)
                    .secondaryColor(secondaryColor)
                    .logo(logoUrl)
                    .build();
        }

        Otp otp = otpService.generateOtp(user, OTPAction.TWO_FACTOR_AUTH);
        return otp.getValidationPayload();
    }


    public static String generateOtp() {
        String characters = "0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder(OTP_LENGTH);

        for (int i = 0; i < OTP_LENGTH; i++) {
            int randomIndex = random.nextInt(characters.length());
            otp.append(characters.charAt(randomIndex));
        }
        log.debug("generated otp: " + otp);
        return otp.toString();
    }


    public LoginResponse validate2fOtp(
            VerifyOtpDto verifyOtpDto) throws JsonProcessingException {
        try {
            Otp extractOtpDetails = otpRepository
                    .findByValidationPayload(verifyOtpDto.getValidationId())
                    .orElseThrow(() -> new BadRequestException("Validation key not found"));

            String otp = verifyOtpDto.getOtp();
            String decrypt = cypher.decrypt(verifyOtpDto.getValidationId());
            JsonNode decryptedPayload = objectMapper.readTree(decrypt);
            String action = decryptedPayload.get("action").asText();
            OTPAction otpAction = OTPAction.valueOf(action);
            Long userId = decryptedPayload.get("userId").asLong();

            if (!extractOtpDetails.getValue().equals(otp)) {
                if (!enableDefaultOtp) {
                    throw new BadRequestException("Otp does not match");
                } else if (!defaultOtp.equals(otp)) {
                    throw new BadRequestException("Otp does not match");
                }
            }

            if (isOtpExpired(extractOtpDetails.getUpdatedAt())
                    || extractOtpDetails.isUsed() || extractOtpDetails.getValue() == null) {
                log.error("OTP expired or wrong OTP entered");
                throw new BadRequestException("OTP Expired or Wrong OTP entered");
            }

            if (!otpAction.equals(OTPAction.TWO_FACTOR_AUTH)) {
                log.error("Invalid permission for OTP");
                throw new BadRequestException("Invalid permission for OTP");
            }

            Map<String, Object> payload = new HashMap<>();
            payload.put("userId", userId);
            payload.put("action", otpAction);

            String newValidationPayload = cypher.encrypt(objectMapper.writeValueAsString(payload));
            extractOtpDetails.setValidationPayload(newValidationPayload);
            extractOtpDetails.setUsed(true);
            otpRepository.save(extractOtpDetails);

            User user = userRepository.findById(userId).orElseThrow(
                    () -> new BadRequestException("User not found"));

            List<String> roleNames = user.getRole().stream()
                    .map(Role::getRoleName)
                    .collect(Collectors.toList());

            if (roleNames.isEmpty()) {
                roleNames = Collections.singletonList(RoleType.DEFAULT_ROLE.getValue());
            }

            Set<String> permissions = user.getRole().stream()
                    .flatMap(role -> role.getPermission().stream())
                    .map(Permission::getPermissionName)
                    .collect(Collectors.toSet());

            boolean isTenantAdmin = user.getRole().stream()
                    .anyMatch(role -> role.getId() == tenantAdminRoleId);

            boolean isEndUser = user.getRole().stream()
                    .anyMatch(role -> Objects.equals(
                            role.getRoleName(), RoleType.DEFAULT_ROLE.getValue()));

            if (isTenantAdmin) {
                permissions = new HashSet<>(
                        getFeaturesByTenantId(user.getTenantId()).getPermissions());
            }

            if (isEndUser) {
                permissions = new HashSet<>(
                        handleEndUserLogin(user.getId()));
            }

            String accessToken = generateAccessToken(
                    new AccessTokenClaims(user.getId(),
                            roleNames, user.getTenantId(), permissions),
                    accessTokenExpirationStrategy.getHotelAdminAccessTokenExpiry());

            Optional<Tenant> tenant = Optional.ofNullable(user.getTenantId())
                    .flatMap(tenantRepository::findById);

            String primaryColor = tenant.map(
                    Tenant::getPrimaryColor).map(String::toUpperCase).orElse("#176d5d");
            String secondaryColor = tenant.map(
                    Tenant::getSecondaryColor).map(String::toUpperCase).orElse("#646363");
            String logoUrl = tenant.map(
                            Tenant::getLogo)
                    .orElse("https://portal.mvpin90days.com/assets/logo-light-ypugESCg.png");

            Role roles = new Role();
            roles.setId(2L);
            roles.setRoleDescription("description needed");
            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .roles(roleNames)
                    .userName(user.getUsername())
                    .userId(user.getId())
                    .permissions(permissions)
                    .primaryColor(primaryColor)
                    .secondaryColor(secondaryColor)
                    .logo(logoUrl)
                    .build();
        } catch (JsonProcessingException e) {
            log.error("Error processing JSON: {}", e.getMessage());
            throw new BadRequestException("Invalid OTP data");
        } catch (BadRequestException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error: {}", e.getMessage());
            throw new RuntimeException(
                    "Unexpected error occurred while validating OTP", e);
        }
    }


    public static boolean isOtpExpired(LocalDateTime createOtpInstant) {
        Long difference = Duration.between(createOtpInstant, LocalDateTime.now()).toMinutes();
        return difference > 3;
    }


    public String resendOtp(String previousValidationPayload) throws JsonProcessingException {
        try {
            String decryptedPreviousValidationPayload = cypher.decrypt(previousValidationPayload);
            JsonNode decryptedPayload = objectMapper.readTree(decryptedPreviousValidationPayload);
            Long userId = decryptedPayload.get("userId").asLong();
            String action = decryptedPayload.get("action").asText();
            OTPAction otpAction = OTPAction.valueOf(action);
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UserNotFoundException(
                            "User not found with id: " + userId));
            if (rateLimiterService.isBlocked(user.getEmail())) {
                insightsEventService.sendEvents(
                        InsightsEventId.FAILED_TO_SEND_OTP,
                        previousValidationPayload, Messages.TOO_MANY_ATTEMPTS,
                        false, 429, user.getTenantId(), null
                );
                throw new TooManyAttemptsException(Messages.TOO_MANY_ATTEMPTS);
            }

            boolean validOtpAction = false;

            for (OTPAction singleAction : OTPAction.values()) {
                if (singleAction.equals(otpAction)) {
                    validOtpAction = true;
                    break;
                }
            }

            if (!validOtpAction) {
                rateLimiterService.recordLoginAttempt(user.getEmail());
                throw new BadRequestException("Invalid use of OTP");
            }

            rateLimiterService.recordLoginAttempt(user.getEmail());
            String newOtpValue = generateOtp();
            Otp otp = otpRepository.findByValidationPayload(previousValidationPayload)
                    .orElseThrow(() -> new BadRequestException("Otp validation payload failed"));

            otp.setValue(newOtpValue);
            otp.setResends(otp.getResends() + 1);
            otpRepository.save(otp);

            CommunicationRequest request = new CommunicationRequest();
            request.setChannel(CommunicationChannel.EMAIL.toString());
            request.setUserId(user.getId());
            request.setTenantId(user.getTenantId());

            Map<String, Object> requestPayload = new HashMap<>();

            switch (otpAction) {
                case FORGOT_PASSWORD:
                    requestPayload.put("subject", "Resend OTP for Forgot Password");
                    break;

                case REGISTER:
                    requestPayload.put("subject", "Resend OTP for Account Verification");
                    break;

                case TWO_FACTOR_AUTH:
                    requestPayload.put("subject", "Resend OTP for 2-Factor Authentication");
                    break;

                default:
                    throw new IllegalArgumentException("Unexpected OTP action: " + otpAction);
            }

            requestPayload.put("data", Map.of(
                    "otp", newOtpValue,
                    "userName", user.getUsername()
            ));
            requestPayload.put("category", CommunicationCategory.OTP_VERIFICATION.toString());
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

            return "OTP has been resent successfully.";

        } catch (Exception e) {
            log.error("Error resending OTP: {}", e.getMessage());
            insightsEventService.sendEvents(InsightsEventId.OTP_FAILURE, null,
                    "Failed to resend OTP", false, 400, null, null);
            return "Failed to resend OTP. Please try again.";
        }
    }

    @Transactional
    public Object handleGoogleLogin(GoogleLoginDto googleLoginDto, Long tenantId) {
        insightsEventService.sendEvents(InsightsEventId.GOOGLE_LOGIN_RECEIVED, googleLoginDto,
                Messages.GOOGLE_LOGIN_INITIATED, true, 200, tenantId, null);

        if (!verifyUserFromGoogle(googleLoginDto)) {
            insightsEventService.sendEvents(
                    InsightsEventId.GOOGLE_LOGIN_FAILED, googleLoginDto, Messages.NOT_VERIFIED,
                    false, 401, tenantId, null
            );

            throw new InvalidCredentialException(Messages.NOT_VERIFIED);
        }

        Optional<User> userCheck = userService.getUserByEmail(googleLoginDto.getEmail());
        if (userCheck.isPresent()) {
            insightsEventService.sendEvents(
                    InsightsEventId.GOOGLE_LOGIN_SUCCESS,
                    googleLoginDto, Messages.GOOGLE_LOGIN_SUCCESS,
                    true, 200, tenantId, userCheck.get().getId()
            );
            return getLoginResponse(userCheck.get());
        }

        String displayName = googleLoginDto.getDisplayName();
        String firstName = displayName.split(" ")[0];
        String lastName = "";

        if (displayName.split(" ").length > 1) {
            lastName = displayName.split(" ")[1];
        }

        String random4Digit = String.format("%04d", (int) (Math.random() * 10000));
        String username = firstName + lastName + random4Digit;
        User user = new User(
                firstName, lastName, googleLoginDto.getEmail(),
                generateRandomString(10), username,
                tenantId
        );

        long endUserRoleId = 38L;
        Optional<Role> role = roleRepository.findById(endUserRoleId);
        user.getRole().add(role.get());
        user.setVerified(true);
        user = userService.saveUser(user);

        // Assign default FREE subscription
        Subscription freeSubscription =
                subscriptionRepository.findBySubscription(SubscriptionType.FREE)
                        .orElseThrow(() -> new
                                SubscriptionNotFoundException("FREE subscription not found"));
        UserSubscription userSubscription = new UserSubscription();
        userSubscription.setId(user.getFirstName() + ":" + user.getId());
        userSubscription.setUser(user);
        userSubscription.setSubscription(freeSubscription);
        userSubscription.setStartDate(LocalDateTime.now());
        userSubscription.setEndDate(null); // Unlimited access for FREE tier
        userSubscription.setOrderStatus("ACTIVE");
        userSubscriptionRepository.save(userSubscription);

        insightsEventService.sendEvents(
                InsightsEventId.GOOGLE_LOGIN_SUCCESS, googleLoginDto, Messages.GOOGLE_LOGIN_SUCCESS,
                true, 200, tenantId, user.getId()
        );

        return getLoginResponse(user);
    }

    @Transactional
    public Object handleFacebookLogin(FacebookLoginDto facebookLoginDto, Long tenantId) {
        insightsEventService.sendEvents(InsightsEventId.FACEBOOK_LOGIN_RECEIVED, facebookLoginDto,
                Messages.FACEBOOK_LOGIN_INITIATED, true, 200, tenantId, null);

        if (!verifyUserFromFacebook(facebookLoginDto)) {
            insightsEventService.sendEvents(
                    InsightsEventId.FACEBOOK_LOGIN_FAILED, facebookLoginDto, Messages.NOT_VERIFIED,
                    false, 401, tenantId, null
            );
            throw new InvalidCredentialException(Messages.NOT_VERIFIED);
        }

        Optional<User> userCheck = userService.getUserByEmail(facebookLoginDto.getEmail());
        if (userCheck.isPresent()) {
            insightsEventService.sendEvents(
                    InsightsEventId.FACEBOOK_LOGIN_SUCCESS,
                    facebookLoginDto, Messages.FACEBOOK_LOGIN_SUCCESS,
                    true, 200, tenantId, userCheck.get().getId()
            );

            return getLoginResponse(userCheck.get());
        }

        String displayName = facebookLoginDto.getDisplayName();
        String firstName = displayName.split(" ")[0];
        String lastName = "";

        if (displayName.split(" ").length > 1) {
            lastName = displayName.split(" ")[1];
        }

        String random4Digit = String.format("%04d", (int) (Math.random() * 10000));
        String username = firstName + lastName + random4Digit;

        User user = new User(
                firstName, lastName, facebookLoginDto.getEmail(),
                generateRandomString(10), username,
                tenantId
        );

        long endUserRoleId = 38L;
        Optional<Role> role = roleRepository.findById(endUserRoleId);
        user.getRole().add(role.get());
        user.setVerified(true);

        user = userService.saveUser(user);

        // Assign default FREE subscription
        Subscription freeSubscription =
                subscriptionRepository.findBySubscription(SubscriptionType.FREE)
                        .orElseThrow(() -> new
                                SubscriptionNotFoundException("FREE subscription not found"));
        UserSubscription userSubscription = new UserSubscription();
        userSubscription.setId(user.getFirstName() + ":" + user.getId());
        userSubscription.setUser(user);
        userSubscription.setSubscription(freeSubscription);
        userSubscription.setStartDate(LocalDateTime.now());
        userSubscription.setEndDate(null); // Unlimited access for FREE tier
        userSubscription.setOrderStatus("ACTIVE");
        userSubscriptionRepository.save(userSubscription);

        insightsEventService.sendEvents(
                InsightsEventId.FACEBOOK_LOGIN_SUCCESS,
                facebookLoginDto, Messages.FACEBOOK_LOGIN_SUCCESS,
                true, 200, tenantId, user.getId()
        );

        return getLoginResponse(user);
    }

    @Transactional
    public Object handleAppleLogin(AppleLoginDto appleLoginDto, Long tenantId) {

        insightsEventService.sendEvents(InsightsEventId.APPLE_LOGIN_RECEIVED, appleLoginDto,
                Messages.APPLE_LOGIN_INITIATED, true, 200, tenantId, null);

        if (!verifyUserFromApple(appleLoginDto)) {
            insightsEventService.sendEvents(
                    InsightsEventId.APPLE_LOGIN_FAILED, appleLoginDto, Messages.NOT_VERIFIED,
                    false, 401, tenantId, null
            );

            throw new InvalidCredentialException(Messages.NOT_VERIFIED);
        }

        Optional<User> userCheck = userRepository.findByAppleId(appleLoginDto.getAppleId());
        if (userCheck.isPresent()) {
            insightsEventService.sendEvents(
                    InsightsEventId.APPLE_LOGIN_SUCCESS, appleLoginDto,
                    Messages.APPLE_LOGIN_SUCCESS,
                    true, 200, tenantId, userCheck.get().getId()
            );

            return getLoginResponse(userCheck.get());
        }


        String random4Digit = String.format("%04d", (int) (Math.random() * 10000));
        String username = appleLoginDto.getFirstName() + appleLoginDto.getLastName() + random4Digit;

        User user = new User(
                appleLoginDto.getFirstName(), appleLoginDto.getLastName(), appleLoginDto.getEmail(),
                generateRandomString(10),
                username,
                tenantId, appleLoginDto.getAppleId()
        );

        long endUserRoleId = 38L;
        Optional<Role> role = roleRepository.findById(endUserRoleId);
        user.getRole().add(role.get());
        user.setVerified(true);
        user = userService.saveUser(user);

        // Assign default FREE subscription
        Subscription freeSubscription =
                subscriptionRepository.findBySubscription(SubscriptionType.FREE)
                        .orElseThrow(() -> new
                                SubscriptionNotFoundException("FREE subscription not found"));
        UserSubscription userSubscription = new UserSubscription();
        userSubscription.setId(user.getFirstName() + ":" + user.getId());
        userSubscription.setUser(user);
        userSubscription.setSubscription(freeSubscription);
        userSubscription.setStartDate(LocalDateTime.now());
        userSubscription.setEndDate(null); // Unlimited access for FREE tier
        userSubscription.setOrderStatus("ACTIVE");
        userSubscriptionRepository.save(userSubscription);


        insightsEventService.sendEvents(
                InsightsEventId.APPLE_LOGIN_SUCCESS,
                appleLoginDto, Messages.APPLE_LOGIN_SUCCESS,
                true, 200, tenantId, user.getId()
        );

        return getLoginResponse(user);
    }

    @Transactional
    public ResponseEntity<RefreshTokenResponseDto> handleRefreshToken(
            RefreshTokenRequestDto requestDto, Long tenantId) {
        String refreshTokenHash = hashRefreshToken(requestDto.getRefreshToken());
        Optional<RefreshToken> refreshTokenOpt =
                refreshTokenRepository.findByToken(refreshTokenHash);

        if (refreshTokenOpt.isEmpty()) {
            throw new InvalidCredentialException("Invalid refresh token.");
        }

        RefreshToken refreshToken = refreshTokenOpt.get();
        if (refreshToken.getLastUsed().plusDays(7).isBefore(LocalDateTime.now())) {
            refreshToken.setRevoked(true);
            refreshTokenRepository.save(refreshToken);

            return ResponseEntity.badRequest().body(RefreshTokenResponseDto.builder()
                    .message("Refresh token expired.")
                    .build());
        }

        if (!refreshToken.getUserId().equals(requestDto.getUserId())) {
            return ResponseEntity.badRequest().body(RefreshTokenResponseDto.builder()
                    .message("Invalid user.")
                    .build());
        }

        String newRefreshToken = generateRefreshToken();
        refreshToken.setRefreshTokenHash(hashRefreshToken(newRefreshToken));
        refreshToken.setLastUsed(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

        User user = userRepository.findById(requestDto.getUserId())
                .orElseThrow(() -> new InvalidCredentialException("User not found."));

        List<String> roleNames = user.getRole().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toList());

        if (roleNames.isEmpty()) {
            roleNames = Collections.singletonList(RoleType.DEFAULT_ROLE.getValue());
        }

        Set<String> permissions = user.getRole().stream()
                .flatMap(role -> role.getPermission().stream())
                .map(Permission::getPermissionName)
                .collect(Collectors.toSet());

        String accessToken = generateAccessToken(
                new AccessTokenClaims(user.getId(), roleNames, user.getTenantId(), permissions),
                accessTokenExpirationStrategy.getHotelAdminAccessTokenExpiry()
        );

        return ResponseEntity.ok(RefreshTokenResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .message("Token refreshed successfully.")
                .build());
    }


    public OtpVerificationResponse verifyOtpAndSetUserVerified(
            String otp, String validationId, Long tenantId
    ) {
        insightsEventService.sendEvents(InsightsEventId.OTP_VERIFICATION_RECEIVED, null,
                Messages.OTP_VERIFICATION_INITIATED, true, 200, tenantId, null);

        Optional<Long> userIdOpt = otpService.validate(otp, validationId);
        if (!userIdOpt.isPresent()) {
            insightsEventService.sendEvents(
                    InsightsEventId.OTP_VERIFICATION_FAILED,
                    null, Messages.OTP_VERIFICATION_FAILED,
                    false, 400, tenantId, null
            );
            return OtpVerificationResponse.failure("Invalid or expired OTP.");
        }

        Long userId = userIdOpt.get();
        User user = userRepository.findById(userId).
                orElseThrow(() -> {
                    insightsEventService.sendEvents(
                            InsightsEventId.OTP_VERIFICATION_FAILED,
                            null, Messages.USER_NOT_FOUND,
                            false, 404, tenantId, userId
                    );

                    return new IllegalStateException("User not found.");
                });
        user.setVerified(true);
        userRepository.save(user);

        try {
            CommunicationRequest request = new CommunicationRequest();
            request.setTenantId(tenantId);
            request.setUserId(userId);
            request.setChannel(CommunicationChannel.EMAIL.toString());

            Map<String, Object> payload = new HashMap<>();
            payload.put("payload", Map.of("userName", user.getUsername()));
            payload.put("subject", "Welcome to MVP in 90 Days");
            payload.put("category", CommunicationCategory.WELCOME_EMAIL.toString());

            request.setPayload(payload);

            ObjectMapper objectMapper = new ObjectMapper();

            httpRequestService.sendPostRequest(
                    messageBaseUrl + "/api/v1/messagebus/event/1",
                    objectMapper.convertValue(request, Map.class)
            );
        } catch (Exception e) {
            log.error("Error while sending email", e);
        }

        insightsEventService.sendEvents(
                InsightsEventId.OTP_VERIFICATION_SUCCESS,
                null, Messages.OTP_VERIFICATION_SUCCESS,
                true, 200, tenantId, userId
        );
        return OtpVerificationResponse.success("User verified successfully.");
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * Generates an access token based on the claim
     *
     * @param expireAfter Access token expiry in days
     */
    private String generateAccessToken(AccessTokenClaims accessTokenClaims, long expireAfter) {
        Consumer<Map<String, Object>> claims = m -> {
            m.put("id", accessTokenClaims.getId());
            m.put("roles", accessTokenClaims.getRole());
            m.put("tenantid", accessTokenClaims.getTenatId());
            m.put("permissions", accessTokenClaims.getPermissions());
        };

        return tokenService.generateToken(claims, expireAfter);
    }

    private Object getLoginResponse(User user) {

        List<String> roleNames = user.getRole().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toList());

        if (roleNames.isEmpty()) {
            roleNames = Collections.singletonList(RoleType.DEFAULT_ROLE.getValue());
        }

        Set<String> permissions = new HashSet<>(handleEndUserLogin(user.getId()));

        String accessToken = generateAccessToken(
                new AccessTokenClaims(user.getId(), roleNames, user.getTenantId(), permissions),
                accessTokenExpirationStrategy.getHotelAdminAccessTokenExpiry()
        );

        Optional<Tenant> tenant = Optional.ofNullable(user.getTenantId())
                .flatMap(tenantRepository::findById);

        String primaryColor = tenant.<String>map(Tenant::getPrimaryColor)
                .map(String::toUpperCase).orElse("#176d5d");
        String secondaryColor = tenant.<String>map(Tenant::getSecondaryColor)
                .map(String::toUpperCase).orElse("#646363");
        String logoUrl = tenant.<String>map(Tenant::getLogo)
                .orElse("https://portal.mvpin90days.com/assets/logo-light-ypugESCg.png");

        if (roleNames.contains(RoleType.DEFAULT_ROLE.getValue())) {

            String refreshToken = getRefreshToken(user.getId());

            return LoginResponseMobile.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .roles(roleNames)
                    .userName(user.getUsername())
                    .userId(user.getId())
                    .permissions(permissions)
                    .primaryColor(primaryColor)
                    .secondaryColor(secondaryColor)
                    .logo(logoUrl)
                    .build();
        }

        return LoginResponse.builder()
                .roles(roleNames)
                .userName(user.getUsername())
                .userId(user.getId())
                .permissions(permissions)
                .primaryColor(primaryColor)
                .secondaryColor(secondaryColor)
                .logo(logoUrl)
                .build();

    }

    private List<String> handleEndUserLogin(Long userId) {
        Optional<UserSubscription> userSubscriptionOpt =
                userSubscriptionRepository.findLatestByUserId(userId);

        if (userSubscriptionOpt.isEmpty()) {
            throw new IllegalArgumentException("No subscription found for user with ID: " + userId);
        }

        UserSubscription userSubscription = userSubscriptionOpt.get();
        Subscription subscription = userSubscription.getSubscription();

        String productId = subscription.getProductId();

        List<FeatureProduct> featureProducts =
                featureProductRepository.findByProductId(productId);

        Set<Long> featureIds = featureProducts.stream()
                .map(FeatureProduct::getFeatureId)
                .collect(Collectors.toSet());

        List<FeaturePermission> featurePermissions =
                featurePermissionRepository.findByFeatureIdIn(featureIds);

        return featurePermissions.stream()
                .map(FeaturePermission::getPermission)
                .map(Permission::getPermissionName)
                .collect(Collectors.toList());
    }

    private static String generateRandomString(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }

        return sb.toString();
    }


    private boolean verifyUserFromGoogle(GoogleLoginDto googleLoginDto) {
        if (googleLoginDto.getDeviceType().equalsIgnoreCase("webapp")) {
            return verifyUserFromGoogleWeb(googleLoginDto);
        } else {
            return verifyUserFromGoogleMobile(googleLoginDto);
        }
    }

    private boolean verifyUserFromGoogleMobile(GoogleLoginDto googleLoginDto) {
        try {
            String url = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token="
                    + googleLoginDto.getToken();
            Map<String, Object> response = httpRequestService.sendGetRequest(url);

            if (!response.containsKey("email")) {
                return false;
            }

            return response.get("email").equals(googleLoginDto.getEmail())
                    && response.get("user_id").equals(googleLoginDto.getId());
        } catch (IOException | InterruptedException e) {
            log.error("Error while verifying user from google", e);
            return false;
        }
    }

    private boolean verifyUserFromGoogleWeb(GoogleLoginDto googleLoginDto) {
        try {
            String url = "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token="
                    + googleLoginDto.getToken();
            Map<String, Object> response = httpRequestService.sendGetRequest(url);

            if (!response.containsKey("email")) {
                return false;
            }

            return response.get("email").equals(googleLoginDto.getEmail())
                    && response.get("sub").equals(googleLoginDto.getId());
        } catch (Exception e) {
            log.error("Error while performing google login verification", e);
            return false;
        }
    }

    private boolean verifyUserFromFacebook(FacebookLoginDto facebookLoginDto) {
        boolean isVerified = false;
        switch (facebookLoginDto.getDeviceType().toLowerCase()) {
            case "android":
                isVerified = facebookVerificationAndroid(facebookLoginDto);
                break;
            case "ios":
                isVerified = facebookVerificationIOS(facebookLoginDto);
                break;
            case "webapp":
                isVerified = facebookVerificationWebapp(facebookLoginDto);
                break;
            default:
                log.error("Invalid device type");
        }

        return isVerified;
    }

    private boolean facebookVerificationAndroid(FacebookLoginDto facebookLoginDto) {
        try {
            String url = "https://graph.facebook.com/me?access_token="
                    + facebookLoginDto.getToken();
            Map<String, Object> response = httpRequestService.sendGetRequest(url);
            return response.get("id").equals(facebookLoginDto.getId());
        } catch (Exception e) {
            log.error("Error while verifying user from google", e);
            return false;
        }
    }

    private boolean facebookVerificationWebapp(FacebookLoginDto facebookLoginDto) {
        try {
            String url = "https://graph.facebook.com/me?access_token="
                    + facebookLoginDto.getToken();
            Map<String, Object> response = httpRequestService.sendGetRequest(url);
            return response.get("id").equals(facebookLoginDto.getId());
        } catch (Exception e) {
            log.error("Error while verifying user from google", e);
            return false;
        }
    }

    private boolean facebookVerificationIOS(FacebookLoginDto facebookLoginDto) {
        try {
            Map<String, Object> claims = jwtDecodeAndVerificationService.
                    verifyJwt(AppConstants.FACEBOOK_JWKS_URI, facebookLoginDto.getToken());
            return claims.get("sub").equals(facebookLoginDto.getId())
                    && claims.get("email").equals(facebookLoginDto.getEmail());
        } catch (Exception e) {
            log.error("Error while performing iOS facebook login verification", e);
            return false;
        }
    }

    private boolean verifyUserFromApple(AppleLoginDto appleLoginDto) {
        try {
            int responseCode = httpRequestService.requestAppleToken(appleLoginDto.getAccessToken());
            return responseCode == 200;
        } catch (Exception e) {
            log.error("Error while verifying user from apple", e);
            return false;
        }
    }

    private String getRefreshToken(Long userId) {
        String refreshToken = generateRefreshToken();

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setUserId(userId);
        refreshTokenEntity.setRefreshTokenHash(hashRefreshToken(refreshToken));
        refreshTokenEntity.setLastUsed(LocalDateTime.now());
        refreshTokenEntity.setRevoked(false);

        refreshTokenRepository.save(refreshTokenEntity);

        return refreshToken;
    }

    private String generateRefreshToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32]; // 256-bit random token
        secureRandom.nextBytes(randomBytes);
        String refreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        return refreshToken;
    }

    @SneakyThrows
    private static String hashRefreshToken(String refreshToken) {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(refreshToken.getBytes("UTF-8"));
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @AllArgsConstructor
    @Getter
    static final class AccessTokenClaims {
        private Long id;
        private List<String> role;
        private Long tenatId;
        private Set<String> permissions;
    }

    private FeatureResponseDto getFeaturesByTenantId(Long tenantId) {
        boolean tenantEnabled = false;
        boolean allUsersEnabled = false;
        boolean tenantUserTicketsEnabled = false;
        boolean tenantAdminTicketsEnabled = false;

        List<Feature> featureList = featureRepository.findFeaturesByTenantId(tenantId);
        if (featureList.isEmpty()) {
            return null;
        }

        for (Feature feature : featureList) {
            if ("Tenants".equals(feature.getFeatureName())) {
                tenantEnabled = true;
            }
            if ("All Users".equals(feature.getFeatureName())) {
                allUsersEnabled = true;
            }
            if ("Tenant User Tickets".equals(
                    feature.getFeatureName())) {
                tenantUserTicketsEnabled = true;
            }
            if ("Tenant Admin Tickets".equals(
                    feature.getFeatureName())) {
                tenantAdminTicketsEnabled = true;
            }
        }
        boolean administrationEnabled =
                tenantEnabled || allUsersEnabled;
        boolean supportEnabled =
                tenantUserTicketsEnabled;

        if (administrationEnabled) {
            Feature result = featureRepository
                    .findByFeatureName("Administration");
            featureList.add(result);
        }
        if (supportEnabled) {
            Feature result = featureRepository
                    .findByFeatureName("Support");
            featureList.add(result);
        }

        Set<FeatureDTO> featureDTOs = featureList.stream()
                .map(feature -> new FeatureDTO(feature.getId(),
                        feature.getFeatureName(),
                        feature.getFeatureDescription(),
                        true))
                .collect(Collectors.toSet());

        Set<Long> featureIds = featureList.stream()
                .map(Feature::getId)
                .collect(Collectors.toSet());

        List<FeaturePermission> featurePermissions =
                featurePermissionRepository.findByFeatureIdIn(featureIds);

        List<String> permissions = featurePermissions.stream()
                .map(fp -> fp.getPermission().getPermissionName())  // Extract permission string
                .collect(Collectors.toList());

        return new FeatureResponseDto(featureDTOs, permissions);
    }

    public OtpVerificationResponse verifyForgotPasswordOtp(
            String otp, String validationId, Long tenantId
    ) {
        insightsEventService.sendEvents(InsightsEventId.OTP_VERIFICATION_RECEIVED, null,
                Messages.OTP_VERIFICATION_INITIATED, true, 200, tenantId, null);

        Optional<Long> userIdOpt = otpService.verify(otp, validationId);
        if (!userIdOpt.isPresent()) {
            insightsEventService.sendEvents(
                    InsightsEventId.OTP_VERIFICATION_FAILED,
                    null, Messages.OTP_VERIFICATION_FAILED,
                    false, 400, tenantId, null
            );
            return OtpVerificationResponse.failure("Invalid or expired OTP.");
        }

        Long userId = userIdOpt.get();
        userRepository.findById(userId).
                orElseThrow(() -> {
                    insightsEventService.sendEvents(
                            InsightsEventId.OTP_VERIFICATION_FAILED,
                            null, Messages.USER_NOT_FOUND,
                            false, 404, tenantId, userId
                    );

                    return new IllegalStateException("OTP can't be verified");
                });

        insightsEventService.sendEvents(
                InsightsEventId.OTP_VERIFICATION_SUCCESS,
                null, Messages.OTP_VERIFICATION_SUCCESS,
                true, 200, tenantId, userId
        );
        return OtpVerificationResponse.success("OTP verified successfully.");
    }
}
