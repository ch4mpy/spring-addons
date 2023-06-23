package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties.RequestParam;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Support two features:
 * <ul>
 * <li>usage of {@link SpringAddonsOAuth2ClientProperties#getClientUri() SpringAddonsOAuth2ClientProperties#client-uri} in post-login redirection URI</li>
 * <li>defining authorization request additional parameters from properties (like audience for Auth0)</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public class SpringAddonsOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

	private final DefaultOAuth2AuthorizationRequestResolver delegate;
	private final Map<String, Consumer<OAuth2AuthorizationRequest.Builder>> authRequestCustomizers = new HashMap<>();
	private final AntPathRequestMatcher authorizationRequestMatcher = new AntPathRequestMatcher(
			OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

	public SpringAddonsOAuth2AuthorizationRequestResolver(
			InMemoryClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOAuth2ClientProperties addonsClientProperties) {
		clientRegistrationRepository.forEach(reg -> {
			final var params = addonsClientProperties.getAuthorizationRequestParams().get(reg.getRegistrationId());
			if (params != null) {
				authRequestCustomizers.put(reg.getRegistrationId(), requestParamAuthorizationRequestCustomizer(params));
			}
		});

		delegate = new DefaultOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository,
				OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		final var registrationId = resolveRegistrationId(request);
		delegate.setAuthorizationRequestCustomizer(authRequestCustomizers.getOrDefault(registrationId, b -> {
		}));
		final var resolved = delegate.resolve(request);
		final var absolute = toAbsolute(resolved, request);
		return absolute;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		delegate.setAuthorizationRequestCustomizer(authRequestCustomizers.getOrDefault(clientRegistrationId, b -> {
		}));
		final var resolved = delegate.resolve(request, clientRegistrationId);
		final var absolute = toAbsolute(resolved, request);
		return absolute;
	}

	private OAuth2AuthorizationRequest toAbsolute(OAuth2AuthorizationRequest defaultAuthorizationRequest, HttpServletRequest request) {
		final var clientUriString = request.getRequestURL();
		if (defaultAuthorizationRequest == null || clientUriString == null) {
			return defaultAuthorizationRequest;
		}
		final var clientUri = URI.create(clientUriString.toString());
		final var redirectUri = UriComponentsBuilder.fromUriString(defaultAuthorizationRequest.getRedirectUri()).scheme(clientUri.getScheme())
				.host(clientUri.getHost()).port(clientUri.getPort()).build().toUriString();
		return OAuth2AuthorizationRequest.from(defaultAuthorizationRequest).redirectUri(redirectUri)
				.authorizationRequestUri(defaultAuthorizationRequest.getAuthorizationRequestUri()).build();
	}

	private String resolveRegistrationId(HttpServletRequest request) {
		if (this.authorizationRequestMatcher.matches(request)) {
			return this.authorizationRequestMatcher.matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
		}
		return null;
	}

	private static Consumer<OAuth2AuthorizationRequest.Builder> requestParamAuthorizationRequestCustomizer(RequestParam[] additionalParams) {
		return customizer -> customizer.authorizationRequestUri(authorizationRequestUri -> {
			for (var reqParam : additionalParams) {
				authorizationRequestUri.queryParam(reqParam.getName(), reqParam.getValue());
			}
			return authorizationRequestUri.build();
		});
	}
}