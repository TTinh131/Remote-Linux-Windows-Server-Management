package com.example.ct491;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class Ct491Application {

	public static void main(String[] args) {
		SpringApplication.run(Ct491Application.class, args);
		System.out.println("The Spring Boot application has started.");
	}
}
