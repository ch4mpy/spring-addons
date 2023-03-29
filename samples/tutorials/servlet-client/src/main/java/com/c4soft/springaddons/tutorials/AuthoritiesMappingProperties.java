package com.c4soft.springaddons.tutorials;

import java.net.URL;
import java.util.stream.Stream;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "authorities-mapping")
public class AuthoritiesMappingProperties {
	private IssuerAuthoritiesMappingProperties[] issuers;

	@Data
	static class IssuerAuthoritiesMappingProperties {
		private URL uri;
		IssuerAuthoritiesMappingProperties.ClaimMappingProperties[] claims;

		@Data
		static class ClaimMappingProperties {
			String jsonPath;
			private ClaimMappingProperties.CaseProcessing caseProcessing = CaseProcessing.UNCHANGED;
			private String prefix = "";

			static enum CaseProcessing {
				UNCHANGED, TO_LOWER, TO_UPPER
			}
		}
	}

	public AuthoritiesMappingProperties.IssuerAuthoritiesMappingProperties get(URL issuerUri) throws AuthoritiesMappingProperties.MisconfigurationException {
		final var issuerProperties = Stream.of(issuers).filter(iss -> issuerUri.equals(iss.getUri())).toList();
		if (issuerProperties.size() == 0) {
			throw new MisconfigurationException("Missing authorities mapping properties for %s".formatted(issuerUri.toString()));
		}
		if (issuerProperties.size() > 1) {
			throw new MisconfigurationException("Too many authorities mapping properties for %s".formatted(issuerUri.toString()));
		}
		return issuerProperties.get(0);
	}

	static class MisconfigurationException extends RuntimeException {
		private static final long serialVersionUID = 5887967904749547431L;

		public MisconfigurationException(String msg) {
			super(msg);
		}
	}
}