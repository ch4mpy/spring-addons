package com.c4soft.springaddons.tutorials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class ResourceServerWithUiApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerWithUiApplication.class, args);
	}

}
