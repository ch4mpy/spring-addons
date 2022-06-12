package com.c4soft.springaddons.tutorials;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.config.Jwt2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.spring.GenericMethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oauth2.spring.GenericMethodSecurityExpressionRoot;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	@Bean
	public SynchronizedJwt2AuthenticationConverter<OAuthentication<ProxiesClaimSet>> authenticationConverter(Jwt2AuthoritiesConverter authoritiesConverter) {
		return jwt -> new OAuthentication<>(new ProxiesClaimSet(jwt.getClaims()), authoritiesConverter.convert(jwt), jwt.getTokenValue());
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