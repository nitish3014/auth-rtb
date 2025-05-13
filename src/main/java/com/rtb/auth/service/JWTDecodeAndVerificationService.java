package com.rtb.auth.service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@Service
public class JWTDecodeAndVerificationService {

    public Map<String, Object> verifyJwt(String jwksUri, String token) throws Exception {
        // Create JWK provider
        JwkProvider provider = new JwkProviderBuilder(new URL(jwksUri)).build();

        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = parts[1];

        // Decode the JWT without validation to get the key ID
        Jwt<Header, Claims> untrusted = Jwts.parser()
                .parseClaimsJwt(header + "." + payload + ".");

        String kid = untrusted.getHeader().get("kid").toString();

        // Fetch the JWK using the kid
        Jwk jwk = provider.get(kid);
        RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();

        // Verify the token using the public key
        Map<String, Object> claims = Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(token)
                .getBody();

        return claims;
    }
}
