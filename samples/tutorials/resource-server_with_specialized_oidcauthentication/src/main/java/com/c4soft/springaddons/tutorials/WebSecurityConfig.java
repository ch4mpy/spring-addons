package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.spring.MethodSecurityExpressionRoot;

import lombok.Data;
import lombok.EqualsAndHashCode;

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

	@Data
	public static class Proxy {
		private final String proxiedSubject;
		private final String tenantSubject;
		private final Set<String> permissions;

		public Proxy(String proxiedSubject, String tenantSubject, Collection<String> permissions) {
			this.proxiedSubject = proxiedSubject;
			this.tenantSubject = tenantSubject;
			this.permissions = Collections.unmodifiableSet(new HashSet<>(permissions));
		}

		public boolean can(String permission) {
			return permissions.contains(permission);
		}
	}

	@Data
	@EqualsAndHashCode(callSuper = true)
	public static class MyAuthentication extends OidcAuthentication<OidcToken> {
		private static final long serialVersionUID = 6856299734098317908L;

		private final Map<String, Proxy> proxies;

		public MyAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Map<String, Proxy> proxies, String bearerString) {
			super(token, authorities, bearerString);
			this.proxies = Collections.unmodifiableMap(proxies);
		}

		public Proxy getProxyFor(String proxiedUserSubject) {
			return this.proxies.getOrDefault(proxiedUserSubject, new Proxy(proxiedUserSubject, getToken().getSubject(), List.of()));
		}
	}

	@Component
	public static class MyMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

		@Override
		protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
			final var root = new MyMethodSecurityExpressionRoot();
			root.setThis(invocation.getThis());
			root.setPermissionEvaluator(getPermissionEvaluator());
			root.setTrustResolver(getTrustResolver());
			root.setRoleHierarchy(getRoleHierarchy());
			root.setDefaultRolePrefix(getDefaultRolePrefix());
			return root;
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
	}
}