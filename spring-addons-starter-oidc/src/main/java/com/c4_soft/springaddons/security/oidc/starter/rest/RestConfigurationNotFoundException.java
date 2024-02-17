package com.c4_soft.springaddons.security.oidc.starter.rest;

public class RestConfigurationNotFoundException extends RuntimeException {
    private static final long serialVersionUID = -1174591896184901571L;

    public RestConfigurationNotFoundException(String clientName) {
        super("No spring-addons OAuth2 client properties for a REST client named %s".formatted(clientName));
    }
}