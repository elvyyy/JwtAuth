package com.example.jwtauth.exception;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UsernamePasswordNotExistException extends RuntimeException {

    public UsernamePasswordNotExistException(String message) {
        super(message);
    }

}
