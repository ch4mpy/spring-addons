package org.springframework.security.test.configuration;

import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
public class JwtTestConfiguration {

	@MockBean
	JwtDecoder jwtDecoder;

	JwtDecoder jwtDecoder() {
		return jwtDecoder;
	}
}
