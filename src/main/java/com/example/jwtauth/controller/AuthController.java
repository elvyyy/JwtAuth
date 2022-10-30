package com.example.jwtauth.controller;

import com.example.jwtauth.dto.SignUpRq;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public record AuthController() {

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void createUser(SignUpRq signUpRq) {

    }

}
