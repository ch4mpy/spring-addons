package com.c4_soft.springaddons.security.oidc.starter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;

public class CompositeOAuth2AuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {
    private final List<Consumer<OAuth2AuthorizationRequest.Builder>> delegates;

    public CompositeOAuth2AuthorizationRequestCustomizer(Consumer<OAuth2AuthorizationRequest.Builder>... customizers) {
        delegates = new ArrayList<>(customizers.length + 3);
        Collections.addAll(delegates, customizers);
    }

    @Override
    public void accept(Builder t) {
        for (var consumer : delegates) {
            consumer.accept(t);
        }
    }

    public CompositeOAuth2AuthorizationRequestCustomizer addCustomizer(Consumer<OAuth2AuthorizationRequest.Builder> customizer) {
        this.delegates.add(customizer);
        return this;
    }

}
