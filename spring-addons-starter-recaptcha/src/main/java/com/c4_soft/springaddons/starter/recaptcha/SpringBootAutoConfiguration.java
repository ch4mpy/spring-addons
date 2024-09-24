package com.c4_soft.springaddons.starter.recaptcha;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import({ C4ReCaptchaSettings.class, C4ReCaptchaValidationService.class })
public class SpringBootAutoConfiguration {

}
