package com.rtb.auth.service;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int TIME_WINDOW_MINUTES = 1;

    private final ConcurrentHashMap<String, LoginAttempt> attemptsCache = new ConcurrentHashMap<>();

    public boolean isBlocked(String email) {
        LoginAttempt attempt = attemptsCache.get(email);

        if (attempt == null) {
            return false;
        }

        long minutesSinceFirstAttempt = ChronoUnit.MINUTES.between(
                attempt.getFirstAttempt(), LocalDateTime.now());

        if (minutesSinceFirstAttempt > TIME_WINDOW_MINUTES) {
            attemptsCache.remove(email);
            return false;
        }

        return attempt.getAttempts() >= MAX_ATTEMPTS;
    }

    public void recordLoginAttempt(String email) {
        attemptsCache.compute(email, (key, attempt) -> {
            if (attempt == null || ChronoUnit.MINUTES.between(
                    attempt.getFirstAttempt(), LocalDateTime.now()) > TIME_WINDOW_MINUTES) {
                return new LoginAttempt(1, LocalDateTime.now());
            }
            attempt.incrementAttempts();
            return attempt;
        });
    }

    public void resetAttempts(String email) {
        attemptsCache.remove(email);
    }

    private static class LoginAttempt {
        private int attempts;
        private LocalDateTime firstAttempt;

        public LoginAttempt(int attempts, LocalDateTime firstAttempt) {
            this.attempts = attempts;
            this.firstAttempt = firstAttempt;
        }

        public int getAttempts() {
            return attempts;
        }

        public LocalDateTime getFirstAttempt() {
            return firstAttempt;
        }

        public void incrementAttempts() {
            this.attempts++;
        }
    }
}
