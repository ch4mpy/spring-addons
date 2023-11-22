package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.io.IOException;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * Provide with <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> for authorization-servers fully compliant with
 * OIDC standard as well as those "almost" implementing the spec. It is (auto)configured with {@link SpringAddonsOidcClientProperties}.
 * </p>
 * <p>
 * <b>This implementation is not multi-tenant ready</b>. It will terminate the user session on this application as well as on a single authorization-server (the
 * one which emitted the access-token with which the logout request is made).
 * </p>
 * <p>
 * This bean is auto-configured by {@link SpringAddonsOidcClientBeans} as {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBean} of type
 * {@link LogoutSuccessHandler}. Usage:
 * </p>
 *
 * <pre>
 * SecurityFilterChain uiFilterChain(HttpSecurity http, LogoutSuccessHandler logoutSuccessHandler) {
 * 	http.logout().logoutSuccessHandler(logoutSuccessHandler);
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOAuth2LogoutRequestUriBuilder
 * @see    SpringAddonsOidcClientProperties
 */
@EqualsAndHashCode(callSuper = true)
public class SpringAddonsLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
	private final LogoutRequestUriBuilder uriBuilder;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final C4Oauth2RedirectStrategy redirectStrategy;

	public SpringAddonsLogoutSuccessHandler(
			LogoutRequestUriBuilder uriBuilder,
			ClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOidcProperties addonsProperties) {
		this.uriBuilder = uriBuilder;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.redirectStrategy = new C4Oauth2RedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getRpInitiatedLogout());
	}

	@Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		if (authentication instanceof OAuth2AuthenticationToken oauth) {
			final var clientRegistration = clientRegistrationRepository.findByRegistrationId(oauth.getAuthorizedClientRegistrationId());
			return uriBuilder.getLogoutRequestUri(clientRegistration, oauth.getName());
		}
		return null;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		this.redirectStrategy.sendRedirect(request, response, determineTargetUrl(request, response));
	}
}