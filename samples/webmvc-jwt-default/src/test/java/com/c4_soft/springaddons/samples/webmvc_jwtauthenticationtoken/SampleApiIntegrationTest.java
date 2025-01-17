package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;

/**
 * <h2>Integration-test for the application</h2>
 * <p>
 * Nothing but the HTTP request is mocked: real controllers, services, repositories and other components are wired together.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import({ AddonsWebmvcTestConf.class })
@AutoConfigureMockMvc
class SampleApiIntegrationTest {

	@Autowired
	MockMvc api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsCh4mp_whenGetGreet_thenOk() throws Exception {
		api.perform(get("/greet")).andExpect(content().string("Hello ch4mp! You are granted with [USER_ROLES_EDITOR, ROLE_AUTHORIZED_PERSONNEL]."));
	}

}
