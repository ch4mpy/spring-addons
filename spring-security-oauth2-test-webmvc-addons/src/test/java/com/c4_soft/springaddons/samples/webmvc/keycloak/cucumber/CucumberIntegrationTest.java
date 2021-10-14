package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber;

import org.junit.runner.RunWith;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;

@RunWith(Cucumber.class)
@CucumberOptions(features = "classpath:cucumber-features", plugin = {
		"pretty",
		"html:target/cucumber" }, extraGlue = "com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.extraglue")
public class CucumberIntegrationTest {
}
