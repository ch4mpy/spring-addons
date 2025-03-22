package com.c4_soft.springaddons.rest;

public class RestMisconfigurationException extends RuntimeException {
  private static final long serialVersionUID = 681577983030933423L;

  public RestMisconfigurationException(String message) {
    super(message);
  }

  public RestMisconfigurationException(Throwable e) {
    super(e);
  }
}
