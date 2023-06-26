package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@AutoConfigureAddonsWebSecurity
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithUiApplicationTests {
	@Autowired
	MockMvcSupport api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
		api.get("/api/greet").andExpect(status().isUnauthorized());
	}

	@TestAsCh4mp
	void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
		api.get("/api/greet").andExpect(status().isOk())
				.andExpect(content().string("Hi ch4mp! You are authenticated by https://dev-ch4mpy.eu.auth0.com/ and granted with: [NICE, AUTHOR]."));
	}
}
