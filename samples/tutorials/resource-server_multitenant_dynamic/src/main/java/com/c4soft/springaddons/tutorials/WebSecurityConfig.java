package com.c4soft.springaddons.tutorials;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.JwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.MissingAuthorizationServerConfigurationException;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.IssuerProperties;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {
	@Bean
	JwtAbstractAuthenticationTokenConverter authenticationConverter(
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
			DynamicTenantProperties addonsProperties) {
		return jwt -> {
			final var issProperties = addonsProperties.getIssuerProperties(jwt.getClaims().get(JwtClaimNames.ISS).toString());
			return new OAuthentication<>(
					new OpenidClaimSet(jwt.getClaims(), issProperties.getUsernameClaim()),
					authoritiesConverter.convert(jwt.getClaims()),
					jwt.getTokenValue());
		};
	}

	private static URI baseUri(URI uri) {
		if (uri == null) {
			return null;
		}
		try {
			return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
		} catch (URISyntaxException e) {
			throw new InvalidIssuerException(uri.toString());
		}
	}

	@Primary
	@Component
	static class DynamicTenantProperties extends SpringAddonsSecurityProperties {

		@Override
		public IssuerProperties getIssuerProperties(String iss) throws MissingAuthorizationServerConfigurationException {
			return super.getIssuerProperties(baseUri(URI.create(iss)).toString());
		}

	}

	@Component
	static class DynamicTenantsAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {
		private final Set<String> issuerBaseUris;
		private final Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter;
		private final Map<String, JwtAuthenticationProvider> jwtManagers = new ConcurrentHashMap<>();
		private final JwtIssuerAuthenticationManagerResolver delegate =
				new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) this::getAuthenticationManager);

		public DynamicTenantsAuthenticationManagerResolver(
				SpringAddonsSecurityProperties addonsProperties,
				Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
			this.issuerBaseUris = Stream.of(addonsProperties.getIssuers()).map(IssuerProperties::getLocation).map(WebSecurityConfig::baseUri).map(URI::toString)
					.collect(Collectors.toSet());
			this.jwtAuthenticationConverter = jwtAuthenticationConverter;
		}

		@Override
		public AuthenticationManager resolve(HttpServletRequest context) {
			return delegate.resolve(context);
		}

		public AuthenticationManager getAuthenticationManager(String issuerUriString) {
			final var issuerBaseUri = baseUri(URI.create(issuerUriString)).toString();
			if (!issuerBaseUris.contains(issuerBaseUri)) {
				throw new InvalidIssuerException(issuerUriString);
			}
			if (!this.jwtManagers.containsKey(issuerUriString)) {
				this.jwtManagers.put(issuerUriString, getProvider(issuerUriString));
			}
			return jwtManagers.get(issuerUriString)::authenticate;
		}

		private JwtAuthenticationProvider getProvider(String issuerUriString) {
			var provider = new JwtAuthenticationProvider(JwtDecoders.fromIssuerLocation(issuerUriString));
			provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
			return provider;
		}
	}

	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	static class InvalidIssuerException extends RuntimeException {
		private static final long serialVersionUID = 4431133205219303797L;

		public InvalidIssuerException(String issuerUriString) {
			super("Issuer %s is not trusted".formatted(issuerUriString));
		}
	}
}