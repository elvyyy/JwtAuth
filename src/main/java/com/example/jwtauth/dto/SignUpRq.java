package com.example.jwtauth.dto;

public record SignUpRq(String username, String email, byte[] password) {
}
