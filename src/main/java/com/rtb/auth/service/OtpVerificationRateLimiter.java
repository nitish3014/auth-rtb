package com.rtb.auth.service;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OtpVerificationRateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final int TIME_WINDOW_MINUTES = 1;

    private final ConcurrentHashMap<String, AttemptTracker> attemptsMap
            = new ConcurrentHashMap<>();

    public boolean isBlocked(String validationId, String ip) {
        String key = generateKey(validationId, ip);
        AttemptTracker tracker = attemptsMap.get(key);

        if (tracker == null) {
            return false;
        }

        long minutesElapsed = ChronoUnit.MINUTES
                .between(tracker.getFirstAttemptTime(), LocalDateTime.now());
        if (minutesElapsed > TIME_WINDOW_MINUTES) {
            attemptsMap.remove(key);
            return false;
        }

        return tracker.getAttemptCount() >= MAX_ATTEMPTS;
    }

    public void recordAttempt(String validationId, String ip) {
        String key = generateKey(validationId, ip);
        attemptsMap.compute(key, (k, tracker) -> {
            if (tracker == null || ChronoUnit.MINUTES.between(
                            tracker.getFirstAttemptTime(),
                            LocalDateTime.now()) > TIME_WINDOW_MINUTES
            ) {
                return new AttemptTracker(1, LocalDateTime.now());
            }
            tracker.incrementAttemptCount();
            return tracker;
        });
    }

    public void resetAttempts(String validationId, String ip) {
        attemptsMap.remove(generateKey(validationId, ip));
    }

    private String generateKey(String validationId, String ip) {
        return validationId + ":" + ip;
    }

    private static class AttemptTracker {
        private int attemptCount;
        private LocalDateTime firstAttemptTime;

        public AttemptTracker(int attemptCount,
                              LocalDateTime firstAttemptTime) {
            this.attemptCount = attemptCount;
            this.firstAttemptTime = firstAttemptTime;
        }

        public int getAttemptCount() {
            return attemptCount;
        }

        public LocalDateTime getFirstAttemptTime() {
            return firstAttemptTime;
        }

        public void incrementAttemptCount() {
            this.attemptCount++;
        }
    }
}

