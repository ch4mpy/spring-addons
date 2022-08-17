package com.c4_soft.springaddons.starter.recaptcha;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({ C4ReCaptchaSettings.class, C4ReCaptchaValidationService.class })
public class SpringBootAutoConfiguration {

}
