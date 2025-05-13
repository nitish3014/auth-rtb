package com.rtb.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Value("${spring.application.name}")
    private String appName;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/actuator/**",
            "/swagger**",
            "/api/v1/auth/{tenantId}/login",
            "/api/v1/auth/v3/**",
            "/api/v1/auth/swagger-ui/**",
            "/api/v1/auth/{tenantId}/google-login",
            "/api/v1/auth/{tenantId}/apple-login",
            "/api/v1/auth/{tenantId}/register/verify-otp",
            "/api/v1/auth/{tenantId}/facebook-login",
            "/api/v1/auth/{tenantId}/refresh-token",
            "/api/v1/auth/{tenantId}/forgot-password/verify-otp"
    );

    @Bean
    public OpenAPI defineOpenApi() {
        Info information = new Info()
                .title(this.appName)
                .version("1.0")
                .description("This API exposes endpoints for Candidate Service");

        OpenAPI openAPI = new OpenAPI().info(information);

        SecurityRequirement securityRequirement = new SecurityRequirement();
        securityRequirement.addList("Bearer Authentication");

        Components components = new Components();
        components.addSecuritySchemes("Bearer Authentication", createAPIKeyScheme());

        openAPI.components(components);

        openAPI.addSecurityItem(securityRequirement);

        return openAPI;
    }

    private SecurityScheme createAPIKeyScheme() {
        return new SecurityScheme().type(SecurityScheme.Type.HTTP)
                .bearerFormat("JWT")
                .scheme("bearer");
    }
}
