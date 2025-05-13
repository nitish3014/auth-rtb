package com.rtb.auth.exception;

/**
 * This exception can be thrown when there is an issue with the client's request,
 * indicating that the request is malformed or invalid.
 */

public class BadRequestException extends RuntimeException {

  public BadRequestException(String message, Throwable ex) {
    super(message, ex);
  }

  public BadRequestException(String message) {
    super(message);
  }

  public BadRequestException(Throwable ex) {
    super(ex);
  }
}
