package com.rtb.auth.exception;

public class ResourceNotFoundException
        extends BadRequestException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
