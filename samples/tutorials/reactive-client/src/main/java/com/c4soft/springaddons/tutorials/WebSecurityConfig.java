package com.c4soft.springaddons.tutorials;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityWebFilterChain clientSecurityFilterChain(
			ServerHttpSecurity http,
			InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
			LogoutProperties logoutProperties) {
		http.addFilterBefore(loginPageWebFilter(), SecurityWebFiltersOrder.LOGIN_PAGE_GENERATING);
		http.oauth2Login();
		http.logout(logout -> {
			logout.logoutSuccessHandler(
					new DelegatingOidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository, logoutProperties, "{baseUrl}"));
		});
		// @formatter:off
		http.authorizeExchange(ex -> ex
				.pathMatchers("/", "/login/**", "/oauth2/**").permitAll()
				.pathMatchers("/nice.html").hasAuthority("NICE")
				.anyExchange().authenticated());
		// @formatter:on
		return http.build();
	}

	private WebFilter loginPageWebFilter() {
		return (ServerWebExchange exchange, WebFilterChain chain) -> {
			return ReactiveSecurityContextHolder.getContext()
					.defaultIfEmpty(
							new SecurityContextImpl(
									new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))))
					.flatMap(ctx -> {
						final var auth = ctx.getAuthentication();
						if (auth != null
								&& auth.isAuthenticated()
								&& !(auth instanceof AnonymousAuthenticationToken)
								&& exchange.getRequest().getPath().toString().equals("/login")) {
							exchange.getResponse().setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
							exchange.getResponse().getHeaders().setLocation(URI.create("/"));
							return exchange.getResponse().setComplete();
						}
						return chain.filter(exchange);
					});
		};
	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "logout")
	static class LogoutProperties {
		private Map<String, ProviderLogoutProperties> registration = new HashMap<>();

		@Data
		static class ProviderLogoutProperties {
			private URI logoutUri;
			private String postLogoutUriParameterName;
		}
	}

	@RequiredArgsConstructor
	static class AlmostOidcClientInitiatedServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
		private final LogoutProperties.ProviderLogoutProperties properties;
		private final ClientRegistration clientRegistration;
		private final String postLogoutRedirectUri;
		private final RedirectServerLogoutSuccessHandler serverLogoutSuccessHandler = new RedirectServerLogoutSuccessHandler();
		private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		// @formatter:off
		return Mono.just(authentication)
				.filter(OAuth2AuthenticationToken.class::isInstance)
				.filter((token) -> authentication.getPrincipal() instanceof OidcUser)
				.map(OAuth2AuthenticationToken.class::cast)
				.flatMap(oauthentication -> {
					final var oidcUser = ((OidcUser) oauthentication.getPrincipal());
					final var endSessionUri = UriComponentsBuilder.fromUri(properties.getLogoutUri())
							.queryParam("client_id", clientRegistration.getClientId())
							.queryParam("id_token_hint", oidcUser.getIdToken().getTokenValue())
							.queryParam(properties.getPostLogoutUriParameterName(), postLogoutRedirectUri(exchange.getExchange().getRequest()).toString()).toUriString();
					return Mono.just(endSessionUri);
				}).switchIfEmpty(this.serverLogoutSuccessHandler.onLogoutSuccess(exchange, authentication).then(Mono.empty()))
				.flatMap((endpointUri) -> this.redirectStrategy.sendRedirect(exchange.getExchange(), URI.create(endpointUri)));
		// @formatter:on
		}

		private String postLogoutRedirectUri(ServerHttpRequest request) {
			if (this.postLogoutRedirectUri == null) {
				return null;
			}
		// @formatter:off
		UriComponents uriComponents = UriComponentsBuilder.fromUri(request.getURI())
				.replacePath(request.getPath().contextPath().value())
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
	static class DelegatingOidcClientInitiatedServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {
		private final Map<String, ServerLogoutSuccessHandler> delegates;

		public DelegatingOidcClientInitiatedServerLogoutSuccessHandler(
				InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
				LogoutProperties properties,
				String postLogoutRedirectUri) {
			delegates = StreamSupport.stream(clientRegistrationRepository.spliterator(), false)
					.collect(Collectors.toMap(ClientRegistration::getRegistrationId, clientRegistration -> {
						final var registrationProperties = properties.getRegistration().get(clientRegistration.getRegistrationId());
						if (registrationProperties == null) {
							final var handler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
							handler.setPostLogoutRedirectUri(postLogoutRedirectUri);
							return handler;
						}
						return new AlmostOidcClientInitiatedServerLogoutSuccessHandler(registrationProperties, clientRegistration, postLogoutRedirectUri);
					}));
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return Mono.just(authentication).filter(OAuth2AuthenticationToken.class::isInstance).map(OAuth2AuthenticationToken.class::cast)
					.flatMap(oauthentication -> delegates.get(oauthentication.getAuthorizedClientRegistrationId()).onLogoutSuccess(exchange, authentication));
		}

	}

	@Data
	@Configuration
	@ConfigurationProperties(prefix = "authorities-mapping")
	public class AuthoritiesMappingProperties {
		private IssuerAuthoritiesMappingProperties[] issuers = {};

		@Data
		static class IssuerAuthoritiesMappingProperties {
			private URL uri;
			private ClaimMappingProperties[] claims;

			@Data
			static class ClaimMappingProperties {
				private String jsonPath;
				private CaseProcessing caseProcessing = CaseProcessing.UNCHANGED;
				private String prefix = "";

				static enum CaseProcessing {
					UNCHANGED, TO_LOWER, TO_UPPER
				}
			}
		}

		public IssuerAuthoritiesMappingProperties get(URL issuerUri) throws MisconfigurationException {
			final var issuerProperties = Stream.of(issuers).filter(iss -> issuerUri.equals(iss.getUri())).toList();
			if (issuerProperties.size() == 0) {
				throw new MisconfigurationException("Missing authorities mapping properties for %s".formatted(issuerUri.toString()));
			}
			if (issuerProperties.size() > 1) {
				throw new MisconfigurationException("Too many authorities mapping properties for %s".formatted(issuerUri.toString()));
			}
			return issuerProperties.get(0);
		}

		static class MisconfigurationException extends RuntimeException {
			private static final long serialVersionUID = 5887967904749547431L;

			public MisconfigurationException(String msg) {
				super(msg);
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
