package com.c4_soft.springaddons.security.oidc.starter;

import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.util.MultiValueMap;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AdditionalParamsAuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {
	private final MultiValueMap<String, String> additionalParams;

	@Override
	public void accept(Builder t) {
		t.additionalParameters(params -> {
			additionalParams.forEach((k, v) -> {
				params.put(k, v.stream().collect(Collectors.joining(",")));
			});
		});
	}

}
