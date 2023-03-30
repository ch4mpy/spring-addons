package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ReactiveApplication {

	public static void main(String[] args) {
		SpringApplication.run(ReactiveApplication.class, args);
	}

}
