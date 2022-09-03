package com.c4soft.springaddons.tutorials;

import java.util.List;
import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2ClaimsConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.spring.C4MethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oauth2.spring.C4MethodSecurityExpressionRoot;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	@Bean
	OAuth2ClaimsConverter<ProxiesClaimSet> claimsConverter() {
		return claims -> new ProxiesClaimSet(claims);
	}

	@Bean
	OAuth2AuthenticationBuilder<ProxiesAuthentication>
			authenticationBuilder(OAuth2ClaimsConverter<ProxiesClaimSet> claimsConverter, OAuth2AuthoritiesConverter authoritiesConverter) {
		return (bearerString, claims) -> {
			final var claimSet = claimsConverter.convert(claims);
			return new ProxiesAuthentication(claimSet, authoritiesConverter.convert(claimSet), bearerString);
		};
	}

	@Bean
	MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
		return new C4MethodSecurityExpressionHandler(ProxiesMethodSecurityExpressionRoot::new);
	}

	static final class ProxiesMethodSecurityExpressionRoot extends C4MethodSecurityExpressionRoot {

		public boolean is(String preferredUsername) {
			return Objects.equals(preferredUsername, getAuthentication().getName());
		}

		public Proxy onBehalfOf(String proxiedUsername) {
			return get(ProxiesAuthentication.class).map(a -> a.getProxyFor(proxiedUsername))
					.orElse(new Proxy(proxiedUsername, getAuthentication().getName(), List.of()));
		}

		public boolean isNice() {
			return hasAnyAuthority("NICE", "SUPER_COOL");
		}
	}
}