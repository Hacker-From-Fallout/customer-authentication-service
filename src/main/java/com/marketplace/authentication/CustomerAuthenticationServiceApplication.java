package com.marketplace.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// TODO разобраться с ensureCustomerUserExists, нужно ли прверять существование сессив регистрации с таким username, сделать проверку на то чтобы username, email не совпадали
// TODO переработать регистрацию 
// TODO разобраться с @JsonProperty и @JsonIgnor
// TODO разобраться с ошибками spring security которые отправляются в ответ
// TODO разобраться с использованием полей от UserDetails

@SpringBootApplication
public class CustomerAuthenticationServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(CustomerAuthenticationServiceApplication.class, args);
	}
}
