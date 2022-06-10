package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.spring.GenericMethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oauth2.spring.GenericMethodSecurityExpressionRoot;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	public interface ProxiesConverter extends Converter<OidcToken, Collection<Proxy>> {
	}

	@Bean
	public ProxiesConverter proxiesConverter() {
		return token -> {
			@SuppressWarnings("unchecked")
			final var proxiesClaim = (Map<String, List<String>>) token.getClaims().get("proxies");
			if (proxiesClaim == null) {
				return List.of();
			}
			return proxiesClaim.entrySet().stream().map(e -> new Proxy(e.getKey(), token.getPreferredUsername(), e.getValue())).toList();
		};
	}

	@Bean
	public SynchronizedJwt2AuthenticationConverter<ProxiesAuthentication> authenticationConverter(
			SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter,
			JwtGrantedAuthoritiesConverter authoritiesConverter,
			ProxiesConverter proxiesConverter) {
		return jwt -> {
			final var token = tokenConverter.convert(jwt);
			final var authorities = authoritiesConverter.convert(jwt);
			final var proxies = proxiesConverter.convert(token);
			return new ProxiesAuthentication(token, authorities, proxies, jwt.getTokenValue());
		};
	}

	@Bean
	public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
		return new GenericMethodSecurityExpressionHandler<>(ProxiesMethodSecurityExpressionRoot::new);
	}

	static final class ProxiesMethodSecurityExpressionRoot extends GenericMethodSecurityExpressionRoot<ProxiesAuthentication> {
		public ProxiesMethodSecurityExpressionRoot() {
			super(ProxiesAuthentication.class);
		}

		public boolean is(String preferredUsername) {
			return getAuth().hasName(preferredUsername);
		}

		public Proxy onBehalfOf(String proxiedUsername) {
			return getAuth().getProxyFor(proxiedUsername);
		}

		public boolean isNice() {
			return hasAnyAuthority("ROLE_NICE_GUY", "SUPER_COOL");
		}
	}
}