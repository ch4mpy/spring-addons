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

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK, classes = { ResourceServerWithOAuthenticationApplication.class, SecurityConfig.class })
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithOAuthenticationApplicationTests {
	@Autowired
	MockMvcSupport mockMvc;

	// @formatter:off
	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isUnauthorized());
	}

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGreetPublic_thenOk() throws Exception {
		mockMvc.get("/greet/public")
			.andExpect(status().isOk())
			.andExpect(content().string("Hello world"));
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mp! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@WithJwt("tonton_proxy_ch4mp.json")
	void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isForbidden());
	}

	@Test
	@WithJwt("tonton_proxy_ch4mp.json")
	void givenUserIsNotGrantedWithNiceButHasProxyForGreetedUser_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/ch4mp")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mp from Tonton Pirate!"));
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsGrantedWithNice_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate from ch4mp!"));
	}

	@Test
	@WithJwt("tonton_proxy_ch4mp.json")
	void givenUserIsNotGrantedWithNiceAndHasNoProxyForGreetedUser_whenGreetOnBehalfOf_thenForbidden() throws Exception {
		mockMvc.get("/greet/on-behalf-of/greeted")
			.andExpect(status().isForbidden());
	}

	@Test
	@WithJwt("tonton_proxy_ch4mp.json")
	void givenUserIsGreetingHimself_whenGreetOnBehalfOf_thenOk() throws Exception {
		mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi Tonton Pirate from Tonton Pirate!"));
	}
	// @formatter:on
}
