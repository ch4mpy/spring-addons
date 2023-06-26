package com.c4soft.springaddons.tutorials;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;

import com.c4_soft.springaddons.security.oauth2.test.annotations.ClasspathClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Test
@WithMockJwtAuth(
		authorities = { "NICE", "AUTHOR" },
		claims = @OpenIdClaims(usernameClaim = "$['https://c4-soft.com/user']['name']", jsonFile = @ClasspathClaims("ch4mp.json")))
public @interface TestAsCh4mp {
}
