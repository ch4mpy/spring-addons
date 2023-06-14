package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.springframework.security.core.context.SecurityContextHolder;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

/**
 * <p>
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedOpenId.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;OpenIdAuthenticationSource({ &#64;OpenId("NICE"), &#64;OpenId("VERY_NICE") })
 * void test(&#64;ParameterizedOpenId OAuthentication&lt;OpenidClaimSet&gt; auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    OpenIdAuthenticationSource
 * @since  6.1.12
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedOpenId.AuthenticationArgumentProcessor.class)
public @interface ParameterizedOpenId {

	@SuppressWarnings("unchecked")
	static class AuthenticationArgumentProcessor extends TypedArgumentConverter<OAuthentication<OpenidClaimSet>, OAuthentication<OpenidClaimSet>> {
		private static Class<OAuthentication<OpenidClaimSet>> clazz;
		static {
			try {
				clazz = (Class<OAuthentication<OpenidClaimSet>>) Class.forName(OAuthentication.class.getName());
			} catch (ClassNotFoundException e) {
			}
		}

		protected AuthenticationArgumentProcessor() {
			super(clazz, clazz);
		}

		@Override
		protected OAuthentication<OpenidClaimSet> convert(OAuthentication<OpenidClaimSet> source) {
			SecurityContextHolder.getContext().setAuthentication(source);

			return source;
		}

	}
}