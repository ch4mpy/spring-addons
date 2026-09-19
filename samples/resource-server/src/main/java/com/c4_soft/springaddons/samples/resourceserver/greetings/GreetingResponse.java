package com.c4_soft.springaddons.samples.resourceserver.greetings;

import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * @param message the greeting
 * @param username the {@code Authentication#getName()}, resolved from the claim configured with
 *        {@code username-claim} for the token issuer
 * @param issuer the {@code iss} claim of the access token
 * @param authorities the authorities mapped from the claims listed in {@code ops[].authorities}
 *        for the token issuer
 */
public record GreetingResponse(String message, @Nullable String username, @Nullable String issuer,
    @Nullable List<String> authorities) {
}
