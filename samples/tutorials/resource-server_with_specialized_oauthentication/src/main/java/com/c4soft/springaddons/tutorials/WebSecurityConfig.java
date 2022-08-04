package com.c4soft.springaddons.tutorials;

import java.util.List;
import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import com.c4_soft.springaddons.security.oauth2.config.ClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.Jwt2ClaimSetConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.spring.C4MethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oauth2.spring.C4MethodSecurityExpressionRoot;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	@Bean
	public Jwt2ClaimSetConverter<ProxiesClaimSet> claimsConverter() {
		return jwt -> new ProxiesClaimSet(jwt.getClaims());
	}

	@Bean
	public SynchronizedJwt2AuthenticationConverter<ProxiesAuthentication> authenticationConverter(
			Jwt2ClaimSetConverter<ProxiesClaimSet> claimsConverter,
			ClaimSet2AuthoritiesConverter<ProxiesClaimSet> authoritiesConverter) {
		return jwt -> {
			final var claims = claimsConverter.convert(jwt);
			return new ProxiesAuthentication(claims, authoritiesConverter.convert(claims), jwt.getTokenValue());
		};
	}

	@Bean
	public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
		return new C4MethodSecurityExpressionHandler(ProxiesMethodSecurityExpressionRoot::new);
	}

	static final class ProxiesMethodSecurityExpressionRoot extends C4MethodSecurityExpressionRoot {

		public boolean is(String preferredUsername) {
			return Objects.equals(preferredUsername, getAuthentication().getName());
		}

		public Proxy onBehalfOf(String proxiedUsername) {
			return get(ProxiesAuthentication.class)
					.map(a -> a.getProxyFor(proxiedUsername))
					.orElse(new Proxy(proxiedUsername, getAuthentication().getName(), List.of()));
		}

		public boolean isNice() {
			return hasAnyAuthority("ROLE_NICE_GUY", "SUPER_COOL");
		}
	}
}