package com.rtb.auth.config;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public record AuthSigningKey(
    RSAPublicKey publicKey,
    RSAPrivateKey privateKey
) {

}