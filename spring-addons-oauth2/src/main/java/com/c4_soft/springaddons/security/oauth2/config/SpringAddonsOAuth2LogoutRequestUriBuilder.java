package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties.OAuth2LogoutProperties;

import lombok.Data;
import lombok.RequiredArgsConstructor;

/**
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@RequiredArgsConstructor
public class SpringAddonsOAuth2LogoutRequestUriBuilder implements LogoutRequestUriBuilder {
	private static final String OIDC_RP_INITIATED_LOGOUT_CONFIGURATION_ENTRY = "end_session_endpoint";
	private static final String OIDC_RP_INITIATED_LOGOUT_CLIENT_ID_REQUEST_PARAM = "client_id";
	private static final String OIDC_RP_INITIATED_LOGOUT_ID_TOKEN_HINT_REQUEST_PARAM = "id_token_hint";
	private static final String OIDC_RP_INITIATED_LOGOUT_POST_LOGOUT_URI_REQUEST_PARAM = "post_logout_redirect_uri";

	private final SpringAddonsOAuth2ClientProperties clientProperties;

	@Override
	public String getLogoutRequestUri(ClientRegistration clientRegistration, String idToken, URI postLogoutUri) {
		final var logoutProps = clientProperties.getLogoutProperties(clientRegistration.getRegistrationId());
		final var logoutEndpointUri = getLogoutEndpointUri(logoutProps, clientRegistration)
				.orElseThrow(() -> new MisconfiguredProviderException(clientRegistration.getRegistrationId()));

		final var builder = UriComponentsBuilder.fromUri(logoutEndpointUri);

		getIdTokenHintRequestParam(logoutProps).ifPresent(idTokenHintParamName -> {
			if (StringUtils.hasText(idToken)) {
				builder.queryParam(idTokenHintParamName, idToken);
			}
		});

		getClientIdRequestParam(logoutProps).ifPresent(clientIdParamName -> {
			if (StringUtils.hasText(clientRegistration.getClientId())) {
				builder.queryParam(clientIdParamName, clientRegistration.getClientId());
			}
		});

		getPostLogoutUriRequestParam(logoutProps).ifPresent(postLogoutUriParamName -> {
			if (postLogoutUri != null && StringUtils.hasText(postLogoutUri.toString())) {
				builder.queryParam(postLogoutUriParamName, postLogoutUri);
			}
		});
		return builder.encode(StandardCharsets.UTF_8).build().toUriString();
	}

	@Override
	public String getLogoutRequestUri(ClientRegistration clientRegistration, String idToken) {
		return getLogoutRequestUri(clientRegistration, idToken, clientProperties.getPostLogoutRedirectUri());
	}

	public Optional<URI> getLogoutEndpointUri(Optional<OAuth2LogoutProperties> logoutProps, ClientRegistration clientRegistration) {
		if (logoutProps.isPresent()) {
			return Optional.ofNullable(logoutProps.get().getUri());
		}
		final var oidcConfig = clientRegistration.getProviderDetails().getConfigurationMetadata();
		return Optional.ofNullable(oidcConfig.get(OIDC_RP_INITIATED_LOGOUT_CONFIGURATION_ENTRY)).map(Object::toString).map(URI::create);
	}

	public Optional<String> getIdTokenHintRequestParam(Optional<OAuth2LogoutProperties> logoutProps) {
		if (logoutProps.isEmpty()) {
			return Optional.of(OIDC_RP_INITIATED_LOGOUT_ID_TOKEN_HINT_REQUEST_PARAM);
		}
		return logoutProps.get().getIdTokenHintRequestParam();
	}

	public Optional<String> getClientIdRequestParam(Optional<OAuth2LogoutProperties> logoutProps) {
		if (logoutProps.isEmpty()) {
			return Optional.of(OIDC_RP_INITIATED_LOGOUT_CLIENT_ID_REQUEST_PARAM);
		}
		return logoutProps.get().getClientIdRequestParam();
	}

	public Optional<String> getPostLogoutUriRequestParam(Optional<OAuth2LogoutProperties> logoutProps) {
		if (logoutProps.isEmpty()) {
			return Optional.of(OIDC_RP_INITIATED_LOGOUT_POST_LOGOUT_URI_REQUEST_PARAM);
		}
		return logoutProps.get().getPostLogoutUriRequestParam();
	}

	static final class MisconfiguredProviderException extends RuntimeException {
		private static final long serialVersionUID = -7076019485141231080L;

		public MisconfiguredProviderException(String clientRegistrationId) {
			super(
					"OAuth2 client registration for %s RP-Initiated Logout is missconfigured: it is neither OIDC complient nor difiend in spring-addons properties"
							.formatted(clientRegistrationId));
		}
	}
}