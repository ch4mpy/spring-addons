package com.c4_soft.springaddons.security.oidc.starter.rest;

public class RestMisconfigurationConfigurationException extends RuntimeException {
    private static final long serialVersionUID = 681577983030933423L;

    public RestMisconfigurationConfigurationException(String clientName) {
        super("REST OAuth2 configuration for %s can be made with a registration ID or Bearer forwarding, but not both at a time".formatted(clientName));
    }
}