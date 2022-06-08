package com.c4soft.springaddons.tutorials;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.spring.MethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oauth2.spring.MethodSecurityExpressionRoot;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	public interface ProxiesConverter extends Converter<Jwt, Map<String, Proxy>> {
	}

	@Bean
	public ProxiesConverter proxiesConverter() {
		return jwt -> {
			@SuppressWarnings("unchecked")
			final var proxiesClaim = (Map<String, List<String>>) jwt.getClaims().get("proxies");
			if (proxiesClaim == null) {
				return Map.of();
			}
			return proxiesClaim.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> new Proxy(e.getKey(), jwt.getSubject(), e.getValue())));
		};
	}

	@Bean
	public SynchronizedJwt2AuthenticationConverter<MyAuthentication> authenticationConverter(
			SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter,
			JwtGrantedAuthoritiesConverter authoritiesConverter,
			ProxiesConverter proxiesConverter) {
		return jwt -> new MyAuthentication(tokenConverter.convert(jwt), authoritiesConverter.convert(jwt), proxiesConverter.convert(jwt), jwt.getTokenValue());
	}

	static final class MyMethodSecurityExpressionRoot extends MethodSecurityExpressionRoot<MyAuthentication> {

		public MyMethodSecurityExpressionRoot() {
			super(MyAuthentication.class);
		}

		public Proxy onBehalfOf(String proxiedUserSubject) {
			return getAuth().getProxyFor(proxiedUserSubject);
		}

		public boolean isNice() {
			return hasAnyAuthority("ROLE_NICE_GUY", "SUPER_COOL");
		}
	}

	@Component
	public static class MyMethodSecurityExpressionHandler extends MethodSecurityExpressionHandler<MyMethodSecurityExpressionRoot> {

		public MyMethodSecurityExpressionHandler() {
			super(MyMethodSecurityExpressionRoot::new);
		}
	}
}