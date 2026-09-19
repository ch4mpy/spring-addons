package com.c4_soft.springaddons.samples.restclient;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Registers {@code @HttpExchange} proxies as beans. The {@code keycloak-admin-group} group is backed
 * by the {@code keycloak-admin-client} REST client (see {@code com.c4-soft.springaddons.rest.group}
 * in {@code application.yml}), so the proxies get its base URL, headers, {@code client_credentials}
 * authorization and request factory.
 *
 * <p>
 * In a real project, these interfaces are usually generated from the consumed API's OpenAPI spec by
 * the {@code openapi-generator-maven-plugin}: nothing left to write to call another service.
 * </p>
 */
@Configuration
@ImportHttpServices(group = "keycloak-admin-group", types = {KeycloakUsersApi.class})
public class HttpServicesConfiguration {
}
