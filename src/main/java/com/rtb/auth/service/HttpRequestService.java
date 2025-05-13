package com.rtb.auth.service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static com.rtb.auth.service.AppConstants.TOKEN_URL;

@Service
@Slf4j
public class HttpRequestService {

    private final HttpClient client;
    private final ObjectMapper objectMapper;
    private final String clientId;
    private final String clientSecret;
    private final String teamId;
    private final String keyId;

    // Constructor to initialize HttpClient and ObjectMapper
    public HttpRequestService(@Value("${apple.client-id}") String clientId,
                               @Value("${apple.client-secret}") String clientSecret,
                               @Value("${apple.team-id}") String teamId,
                               @Value("${apple.key-id}") String keyId) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.teamId = teamId;
        this.keyId = keyId;
        this.client = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    public Map sendGetRequest(String url) throws IOException, InterruptedException {
        // Create the HTTP GET request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        // Send the request and get the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Map the JSON response to Map<String, Object>
        return objectMapper.readValue(response.body(), Map.class);
    }

    public Map sendPostRequest(String url, Map<String, Object> data)
            throws IOException, InterruptedException {
        // Convert the data to JSON
        String json = objectMapper.writeValueAsString(data);

        // Create the HTTP POST request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        // Send the request and get the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        log.error("Response from api testing: {}", response.body());

        // Map the JSON response to Map<String, Object>
        return objectMapper.readValue(response.body(), Map.class);
    }

    public void sendPostRequestWithoutReturn(String url, Map<String, Object> data)
            throws IOException, InterruptedException {
        // Convert the data to JSON
        String json = objectMapper.writeValueAsString(data);

        // Create the HTTP POST request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        // Send the request and get the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        log.error("Response from api testing: {}", response.body());
    }

    public String generateAppleAuthToken() throws Exception {
        String privateKeyContent = clientSecret
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

        // Generate the JWT
        long now = System.currentTimeMillis() / 1000L; // Current time in seconds
        long exp = now + 300; // Expiration time is 5 minutes from now
        Algorithm algorithm = Algorithm.ECDSA256(null, privateKey);

        return JWT.create()
                .withIssuer(teamId)               // iss: Apple Team ID
                .withIssuedAt(new java.util.Date(now * 1000)) // iat: Current timestamp
                .withExpiresAt(new java.util.Date(exp * 1000)) // exp: Expiration timestamp
                .withAudience("https://appleid.apple.com") // aud: Audience
                .withSubject(clientId)            // sub: Client ID
                .withKeyId(keyId)                 // kid: Key ID
                .sign(algorithm);
    }

    public int requestAppleToken(String code) throws Exception {

        String appleToken = generateAppleAuthToken();

        // Data to be sent in the POST request
        Map<String, String> formData = Map.of(
                "client_id", clientId,
                "client_secret", appleToken,
                "code", code,
                "grant_type", "authorization_code"
        );

        // Build the form data
        StringBuilder encodedForm = new StringBuilder();
        for (Map.Entry<String, String> entry : formData.entrySet()) {
            if (!encodedForm.isEmpty()) {
                encodedForm.append("&");
            }
            encodedForm.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }

        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encodedForm.toString()))
                .build();

        log.error("Requesting Apple token with code: {}", code);

        // Send the request and get the response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        log.error("Apple token Status Code: {}", response.statusCode());
        log.error("Apple token response: {}", response.body());

        // Return the response status code and body
        return response.statusCode();
    }
}
