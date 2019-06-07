package com.c4soft.springaddons.showcase;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("jwt")
class KeyConfig {

	@Bean
	KeyPair keyPair() {
		try {
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	        keyPairGenerator.initialize(2048);
	        return keyPairGenerator.generateKeyPair();
		} catch (final Exception e) {
			throw new IllegalArgumentException(e);
		}
	}
}