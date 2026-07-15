package com.ilango.Security_project.controller;

import com.ilango.Security_project.dto.UserResponse;
import com.ilango.Security_project.entity.User;
import com.ilango.Security_project.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final AuthService authService;


    @GetMapping("/hi")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> hi() {
        return ResponseEntity.ok("hi");
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/me")
    public ResponseEntity<UserResponse> profile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(authService.profile(user));
    }
}
