package com.marketplace.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// TODO разобраться с полномочиями и ролями, разобраться с наименованием топиков в kafka

@SpringBootApplication
public class CustomerAuthenticationServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(CustomerAuthenticationServiceApplication.class, args);
	}
}
