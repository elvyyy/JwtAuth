package com.example.jwtauth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class JwtValidationException extends RuntimeException {

    public JwtValidationException(String message) {
        super(message);
    }

}
