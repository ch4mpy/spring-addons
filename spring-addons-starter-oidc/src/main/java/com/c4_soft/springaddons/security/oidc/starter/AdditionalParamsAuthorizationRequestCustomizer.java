package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.RequestParam;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AdditionalParamsAuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {
    private final Collection<RequestParam> additionalParams;

    @Override
    public void accept(Builder t) {
        t.additionalParameters(params -> {
            for (var reqParam : additionalParams) {
                params.put(reqParam.getName(), reqParam.getValue());
            }
        });
    }

}
