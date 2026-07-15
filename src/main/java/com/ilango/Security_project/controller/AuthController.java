package com.ilango.Security_project.controller;

import com.ilango.Security_project.dto.AuthResponse;
import com.ilango.Security_project.dto.LoginRequest;
import com.ilango.Security_project.dto.RegisterRequest;
import com.ilango.Security_project.security.CookieUtil;
import com.ilango.Security_project.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
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
    private final CookieUtil cookieUtil;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request
    ) {

       return new ResponseEntity<>(authService.register(request), HttpStatus.OK);
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse  response) {

        AuthResponse auth=authService.login(request);
        cookieUtil.createAccessTokenCookie(
                auth.getAccessToken(),
                auth.getExpiresIn(),
                response
        );
        cookieUtil.createRefreshTokenCookie(
                auth.getRefreshToken(),
                7 * 24 * 60 * 60,
                response
        );
        auth.setAccessToken(null);
        auth.setRefreshToken(null);

        return ResponseEntity.ok(auth);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(
            @CookieValue(name="refreshToken") String refreshToken,
            HttpServletResponse response
    ){

        AuthResponse auth = authService.refreshToken(refreshToken);

        cookieUtil.createAccessTokenCookie(
                auth.getAccessToken(),
                auth.getExpiresIn(),
                response
                );

        cookieUtil.createRefreshTokenCookie(
                auth.getRefreshToken(),
                7*24*60*60,
                response
                );

        auth.setAccessToken(null);
        auth.setRefreshToken(null);

        return auth;
    }
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(

            @CookieValue(name = "refreshToken", required = false)
            String refreshToken,

            HttpServletResponse response
    ) {

        if (refreshToken != null && !refreshToken.isBlank()) {
            authService.logout(refreshToken);
        }

        cookieUtil.clearCookies(response);

        return ResponseEntity.ok().build();
    }

}