package com.marketplace.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// TODO разобраться с полномочиями и ролями, разобраться с наименованием топиков в kafka
// TODO Вынести логику создания профиля в другой метод и не вызывать ее в методе создания customer

@SpringBootApplication
public class CustomerAuthenticationServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(CustomerAuthenticationServiceApplication.class, args);
	}
}
