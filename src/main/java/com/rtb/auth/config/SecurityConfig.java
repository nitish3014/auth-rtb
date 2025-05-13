package com.rtb.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private final AuthSigningKey authSigningKey;

  public SecurityConfig(AuthSigningKey authSigningKey) {
    this.authSigningKey = authSigningKey;
  }


  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
            .cors(AbstractHttpConfigurer::disable)
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/v1/auth/actuator/**").permitAll()
                    .requestMatchers("/swagger**").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/login").permitAll()
                    .requestMatchers("/api/v1/auth/v3/**").permitAll()
                    .requestMatchers("/api/v1/auth/swagger-ui/**").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/google-login").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/validate-2f-otp").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/resend-otp").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/apple-login").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/register/verify-otp").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/facebook-login").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/refresh-token").permitAll()
                    .requestMatchers("/api/v1/auth/{tenantId}/forgot-password/verify-otp")
                      .permitAll()
                    .anyRequest().authenticated())
            .csrf(AbstractHttpConfigurer::disable).httpBasic(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(
                    jwt -> jwt.jwtAuthenticationConverter(new CustomJwtAuthenticationConverter())))
            .sessionManagement(session
                    -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
              .httpStrictTransportSecurity(hsts -> hsts
                      .includeSubDomains(true)
                      .preload(true)
                      .maxAgeInSeconds(31536000))).build();
  }

  @Bean
  JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withPublicKey(authSigningKey.publicKey()).build();
  }

}

@SuppressWarnings("NullableProblems")
class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter =
          getJwtGrantedAuthoritiesConverter();

  @Override
  public final AbstractAuthenticationToken convert(Jwt jwt) {
    Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
    JwtAuthenticationToken jwtAuthenticationToken =
            new JwtAuthenticationToken(jwt, authorities, null);
    jwtAuthenticationToken.setDetails(jwt.getClaims());

    return jwtAuthenticationToken;
  }

  private Converter<Jwt, Collection<GrantedAuthority>> getJwtGrantedAuthoritiesConverter() {
    JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
    converter.setAuthoritiesClaimName("role");
    converter.setAuthorityPrefix("");
    return converter;
  }

}
