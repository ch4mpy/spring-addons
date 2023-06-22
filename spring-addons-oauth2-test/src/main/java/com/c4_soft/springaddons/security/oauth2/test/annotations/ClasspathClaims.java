package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Map;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StringUtils;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface ClasspathClaims {

	String value() default "";

	static final class Support {

		private Support() {
		}

		public static Map<String, Object> parse(ClasspathClaims claim) {
			if (claim == null || !StringUtils.hasText(claim.value())) {
				return Map.of();
			}

			InputStream cpRessource;
			try {
				cpRessource = new ClassPathResource(claim.value()).getInputStream();
			} catch (IOException e) {
				throw new RuntimeException("Failed to load classpath resource %s as OpenID claims".formatted(claim.value()), e);
			}
			try {
				return new JSONParser(JSONParser.MODE_PERMISSIVE).parse(cpRessource, JSONObject.class);
			} catch (final ParseException | UnsupportedEncodingException e) {
				throw new InvalidJsonException(e);
			}
		}

	}

}
