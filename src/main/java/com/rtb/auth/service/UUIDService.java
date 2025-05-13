package com.rtb.auth.service;

import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class UUIDService {

    public String generateRandomUUID() {
        // Generate a random UUID
        UUID randomUUID = UUID.randomUUID();

        // Convert the UUID to a string and return it
        return randomUUID.toString();
    }
}