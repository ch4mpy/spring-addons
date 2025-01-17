package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.List;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
class TestUserAuthorityRepositoryConf {
	@Bean
	UserAuthorityRepository userAuthorityRepository() {
		final var userAuthorityRepository = mock(UserAuthorityRepository.class);
		when(userAuthorityRepository.findByIdUserSubject("oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e94")).thenReturn(
				List.of(new UserAuthority("oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e94", "ROLE_AUTHORIZED_PERSONNEL", "AUTHORIZED_PERSONNEL")));
		when(userAuthorityRepository.findByIdUserSubject("oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e90")).thenReturn(
				List.of(
						new UserAuthority("oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e90", "UNCLE", "UNCLE"),
						new UserAuthority("oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e90", "SKIPPER", "PIRATE")));
		return userAuthorityRepository;
	}
}