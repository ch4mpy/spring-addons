package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

/**
 * <h2>Integration-test for the application</h2>
 * <p>
 * Nothing but the HTTP request is mocked: real controllers, services, repositories and other components are wired together.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
@TestInstance(Lifecycle.PER_CLASS)
class SampleApiIntegrationTest {
	@Autowired
	MockMvcSupport api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.get("/greet").andExpect(content().string("Hello ch4mp! You are granted with [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL]."));
	}

}
