package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.extraglue;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;

import com.c4_soft.springaddons.samples.webmvc.keycloak.KeycloakSpringBootSampleApp;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

import io.cucumber.spring.CucumberContextConfiguration;

@CucumberContextConfiguration
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@ContextConfiguration(classes = { KeycloakSpringBootSampleApp.class, ServletKeycloakAuthUnitTestingSupport.class })
@AutoConfigureMockMvc
@TestExecutionListeners(listeners = { WithSecurityContextTestExecutionListener.class })
public class CucumberSpringConfiguration {
}
