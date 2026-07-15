package com.ilango.Security_project.service;

import com.ilango.Security_project.dto.*;
import com.ilango.Security_project.entity.AuthProvider;
import com.ilango.Security_project.entity.RefreshToken;
import com.ilango.Security_project.entity.Role;
import com.ilango.Security_project.entity.User;
import com.ilango.Security_project.exception.ApiException;
import com.ilango.Security_project.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthResponse register(RegisterRequest request) {
        if(userRepo.existsByEmail(request.getEmail())) {
            throw new ApiException(HttpStatus.CONFLICT, "Email already exists");
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .provider(AuthProvider.LOCAL)
                .enabled(true)
                .build();

        User savedUser = userRepo.save(user);
        return AuthResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole().name())
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();

        // Generate Access Token
        String accessToken = jwtService.generateAccessToken(user);

        // Create Refresh Token
        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().name())
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .expiresIn(jwtService.getAccessExpiration() / 1000)
                .build();
    }
    @Transactional
    public AuthResponse refreshToken(String refreshTokenValue) {

        RefreshToken refreshToken =
                refreshTokenService.verifyRefreshToken(
                        refreshTokenValue
                );

        User user = refreshToken.getUser();

        RefreshToken newRefreshToken =
                refreshTokenService.rotateRefreshToken(
                        refreshTokenValue
                );

        String accessToken =
                jwtService.generateAccessToken(user);

        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().name())
                .accessToken(accessToken)
                .refreshToken(newRefreshToken.getToken())
                .expiresIn(jwtService.getAccessExpiration() / 1000)
                .build();
    }
    @Transactional
    public void logout(String refreshToken) {

        refreshTokenService.revokeRefreshToken(refreshToken);
    }

    public UserResponse profile(User user) {
        if(user==null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid user");
        }
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}
