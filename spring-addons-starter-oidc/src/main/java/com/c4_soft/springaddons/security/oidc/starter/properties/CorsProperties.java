package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.util.List;

import lombok.Data;

@Data
public class CorsProperties {
    /**
     * Path matcher to which this configuration entry applies
     */
    private String path = "/**";

    /**
     * Default is null
     */
    private Boolean allowCredentials = null;

    /**
     * Default is "*" which allows all origins
     */
    private List<String> allowedOriginPatterns = List.of("*");

    /**
     * Default is "*" which allows all methods
     */
    private List<String> allowedMethods = List.of("*");

    /**
     * Default is "*" which allows all headers
     */
    private List<String> allowedHeaders = List.of("*");

    /**
     * Default is "*" which exposes all headers
     */
    private List<String> exposedHeaders = List.of("*");

    private Long maxAge = null;
}
