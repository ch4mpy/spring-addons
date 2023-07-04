package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * <p>
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedAuthentication.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage on tests decorated with &#64;AutoConfigureAddonsSecurity or &#64;AutoConfigureAddonsWebSecurity:
 *
 * <pre>
 * &#64;Autowired
 * WithJwt.AuthenticationFactory authFactory;
 *
 * &#64;ParameterizedTest
 * &#64;MethodSource("authSource")
 * void givenUserIsPersona_whenGetGreet_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
 *     ...
 * }
 *
 * Stream&lt;AbstractAuthenticationToken&gt; authSource() {
 *     return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    JwtAuthenticationSource
 * @since  6.1.12
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedAuthentication.AuthenticationArgumentProcessor.class)
public @interface ParameterizedAuthentication {

	static class AuthenticationArgumentProcessor extends TypedArgumentConverter<Authentication, Authentication> {

		protected AuthenticationArgumentProcessor() {
			super(Authentication.class, Authentication.class);
		}

		@Override
		protected Authentication convert(Authentication source) {
			SecurityContextHolder.getContext().setAuthentication(source);

			return source;
		}

	}
}