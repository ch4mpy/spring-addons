package com.c4soft.springaddons.tutorials;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4soft.springaddons.tutorials.LogoutProperties.ProviderLogoutProperties;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityFilterChain
			clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository, LogoutProperties logoutProperties)
					throws Exception {
		http.addFilterBefore(new LoginPageFilter(), DefaultLoginPageGeneratingFilter.class);
		http.oauth2Login();
		http.logout(logout -> {
			logout.logoutSuccessHandler(new DelegatingOidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
		});
		// @formatter:off
		http.authorizeHttpRequests(ex -> ex
				.requestMatchers("/", "/login/**", "/oauth2/**").permitAll()
				.requestMatchers("/nice.html").hasAuthority("NICE")
				.anyRequest().authenticated());
		// @formatter:on
		return http.build();
	}

	static class LoginPageFilter extends GenericFilterBean {
		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
			if (SecurityContextHolder.getContext().getAuthentication() != null
					&& SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
					&& ((HttpServletRequest) request).getRequestURI().equals("/login")) {
				((HttpServletResponse) response).sendRedirect("/");
			}
			chain.doFilter(request, response);
		}

	}

	static class AlmostOidcClientInitiatedLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
		public AlmostOidcClientInitiatedLogoutSuccessHandler(
				ProviderLogoutProperties properties,
				ClientRegistration clientRegistration,
				String postLogoutRedirectUri) {
			super();
			this.properties = properties;
			this.clientRegistration = clientRegistration;
			this.postLogoutRedirectUri = postLogoutRedirectUri;
		}

		private final LogoutProperties.ProviderLogoutProperties properties;
		private final ClientRegistration clientRegistration;
		private final String postLogoutRedirectUri;

		@Override
		protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
			if (authentication instanceof OAuth2AuthenticationToken oauthentication && authentication.getPrincipal() instanceof OidcUser oidcUser) {
				final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri()).queryParam("client_id", clientRegistration.getClientId())
						.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
						.queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(request).toString()).toUriString();
				return endSessionUri.toString();
			}
			return super.determineTargetUrl(request, response, authentication);
		}

		private String postLogoutRedirectUri(HttpServletRequest request) {
			if (this.postLogoutRedirectUri == null) {
				return null;
			}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();

		Map<String, String> uriVariables = new HashMap<>();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());

		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");

		String path = uriComponents.getPath();
		uriVariables.put("basePath", (path != null) ? path : "");

		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);

		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		return UriComponentsBuilder.fromUriString(this.postLogoutRedirectUri)
				.buildAndExpand(uriVariables)
				.toUriString();
		// @formatter:on
		}
	}

	@RequiredArgsConstructor
	static class DelegatingOidcClientInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {
		private final Map<String, LogoutSuccessHandler> delegates;

		public DelegatingOidcClientInitiatedLogoutSuccessHandler(
				InMemoryClientRegistrationRepository clientRegistrationRepository,
				LogoutProperties properties,
				String postLogoutRedirectUri) {
			delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
					.collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
						final var registrationProperties = properties.getRegistration().get(clientRegistration.getRegistrationId());
						if (registrationProperties == null) {
							final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
							handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
							return handler;
						}
						return new AlmostOidcClientInitiatedLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
					}));
		}

		@Override
		public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
				throws IOException,
				ServletException {
			if (authentication instanceof OAuth2AuthenticationToken oauthentication) {
				delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(request, response, authentication);
			}
		}

	}

	@Component
	@RequiredArgsConstructor
	static class GrantedAuthoritiesMapperImpl implements GrantedAuthoritiesMapper {
		private final AuthoritiesMappingProperties properties;

		@Override
		public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (OidcUserAuthority.class.isInstance(authority)) {
					final var oidcUserAuthority = (OidcUserAuthority) authority;
					final var issuer = oidcUserAuthority.getIdToken().getClaimAsURL(JwtClaimNames.ISS);
					mappedAuthorities.addAll(extractAuthorities(oidcUserAuthority.getIdToken().getClaims(), properties.get(issuer)));

				} else if (OAuth2UserAuthority.class.isInstance(authority)) {
					try {
						final var oauth2UserAuthority = (OAuth2UserAuthority) authority;
						final var userAttributes = oauth2UserAuthority.getAttributes();
						final var issuer = new URL(userAttributes.get(JwtClaimNames.ISS).toString());
						mappedAuthorities.addAll(extractAuthorities(userAttributes, properties.get(issuer)));

					} catch (MalformedURLException e) {
						throw new RuntimeException(e);
					}
				}
			});

			return mappedAuthorities;
		};

		@SuppressWarnings({ "rawtypes", "unchecked" })
		private static
				Collection<GrantedAuthority>
				extractAuthorities(Map<String, Object> claims, AuthoritiesMappingProperties.IssuerAuthoritiesMappingProperties properties) {
			return Stream.of(properties.claims).flatMap(claimProperties -> {
				Object claim;
				try {
					claim = JsonPath.read(claims, claimProperties.jsonPath);
				} catch (PathNotFoundException e) {
					claim = null;
				}
				if (claim == null) {
					return Stream.empty();
				}
				if (claim instanceof String claimStr) {
					return Stream.of(claimStr.split(","));
				}
				if (claim instanceof String[] claimArr) {
					return Stream.of(claimArr);
				}
				if (Collection.class.isAssignableFrom(claim.getClass())) {
					final var iter = ((Collection) claim).iterator();
					if (!iter.hasNext()) {
						return Stream.empty();
					}
					final var firstItem = iter.next();
					if (firstItem instanceof String) {
						return (Stream<String>) ((Collection) claim).stream();
					}
					if (Collection.class.isAssignableFrom(firstItem.getClass())) {
						return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
					}
				}
				return Stream.empty();
			}).map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
		}
	}
}
