package com.ilango.Security_project.controller;

import com.ilango.Security_project.dto.AuthResponse;
import com.ilango.Security_project.dto.LoginRequest;
import com.ilango.Security_project.dto.RegisterRequest;
import com.ilango.Security_project.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {

       return new ResponseEntity<>(authService.register(request), HttpStatus.OK);
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request){
        return new ResponseEntity<>(authService.login(request),HttpStatus.OK);
    }

}