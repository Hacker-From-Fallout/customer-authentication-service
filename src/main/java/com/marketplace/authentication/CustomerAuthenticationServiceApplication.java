package com.marketplace.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// TODO получать ли при регситраци данные типа boolean, разобраться с ensureCustomerUserExists, нужно ли прверять существование сессив регистрации с таким username

@SpringBootApplication
public class CustomerAuthenticationServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(CustomerAuthenticationServiceApplication.class, args);
	}
}
