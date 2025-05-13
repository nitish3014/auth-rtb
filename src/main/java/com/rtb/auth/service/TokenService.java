package com.rtb.auth.service;
import com.rtb.auth.config.AuthSigningKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.function.Consumer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class TokenService {

  private final AuthSigningKey authSigningKey;
  private final JwtEncoder jwtEncoder;

  public TokenService(AuthSigningKey authSigningKey) {
    this.authSigningKey = authSigningKey;
    this.jwtEncoder = createJwtEncoder();
  }

  public String generateToken(Consumer<Map<String, Object>> claims, long expireAfter) {
    Instant now = Instant.now();
    JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                                         .issuer("self")
                                         .issuedAt(now)
                                         .expiresAt(now.plus(expireAfter, ChronoUnit.DAYS))
                                         .claims(claims)
                                         .build();
    return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
  }

  private JwtEncoder createJwtEncoder() {
    JWK jwk = new RSAKey.Builder(authSigningKey.publicKey())
      .privateKey(authSigningKey.privateKey()).build();
    JWKSource<SecurityContext> jks = new ImmutableJWKSet<>(new JWKSet(jwk));
    return new NimbusJwtEncoder(jks);
  }
}