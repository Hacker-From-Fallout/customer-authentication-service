package com.marketplace.authentication.repositories.specifications;

import org.springframework.data.jpa.domain.Specification;

import com.marketplace.authentication.domain.entities.CustomerUser;

public class CustomerUserSpecifications {

    public static Specification<CustomerUser> hasUsername(String username) {
        return (root, query, criteriaBuilder) -> {
            String searchPattern = username.toLowerCase() + "%";

            return criteriaBuilder.like(
                criteriaBuilder.lower(root.get("username")),
                searchPattern
            );
        };
    }

    public static Specification<CustomerUser> hasEmail(String email) {
        return (root, query, criteriaBuilder) -> {
            String searchPattern = email.toLowerCase() + "%";

            return criteriaBuilder.like(
                criteriaBuilder.lower(root.get("email")),
                searchPattern
            );
        };
    }

    public static Specification<CustomerUser> hasPhoneNumber(String phoneNumber) {
        return (root, query, criteriaBuilder) -> {
            String searchTerm = phoneNumber.trim();

            if (!searchTerm.startsWith("+")) {
                searchTerm = "+" + searchTerm;
            }

            String searchPattern = searchTerm.toLowerCase() + "%";
            return criteriaBuilder.like(
                criteriaBuilder.lower(root.get("phoneNumber")),
                searchPattern
            );
        };
    }
}
