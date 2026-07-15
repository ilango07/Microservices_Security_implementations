package com.ilango.Security_project.security;

import com.ilango.Security_project.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;


    private String getAccessToken(HttpServletRequest request) {

        if (request.getCookies() == null)
            return null;

        for (Cookie cookie : request.getCookies()) {

            if ("accessToken".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // ============================================================
        // STEP 1: Get Access Token from Cookie
        // ============================================================
        String jwt = getAccessToken(request);


        // ============================================================
        // STEP 2: Check if token exists
        // ============================================================

        if (jwt == null || jwt.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        // ============================================================
        // STEP 3: Try to authenticate with the token
        // ============================================================
        try {
            String username = jwtService.extractUsername(jwt);

            // ============================================================
            // STEP 4: Check if user is not already authenticated
            // ============================================================
            if (username != null &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                try {
                    // ============================================================
                    // STEP 5: Load user from database
                    // ============================================================
                    UserDetails userDetails =
                            userDetailsService.loadUserByUsername(username);

                    // ============================================================
                    // STEP 6: Validate the token
                    // ============================================================
                    if (jwtService.isTokenValid(jwt, userDetails)) {

                        // ============================================================
                        // STEP 7: Create authentication object
                        // ============================================================
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );

                        // ============================================================
                        // STEP 8: Set request details
                        // ============================================================
                        authentication.setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(request)
                        );

                        // ============================================================
                        // STEP 9: Set authentication in SecurityContext
                        // ============================================================
                        SecurityContextHolder.getContext()
                                .setAuthentication(authentication);
                    }

                } catch (UsernameNotFoundException e) {
                    // ============================================================
                    // HANDLE: User not found in database
                    // Clear any existing authentication
                    // ============================================================
                    SecurityContextHolder.clearContext();

                } catch (ExpiredJwtException e) {
                    // ============================================================
                    // HANDLE: Token has expired
                    // Clear any existing authentication
                    // ============================================================
                    SecurityContextHolder.clearContext();

                } catch (JwtException | IllegalArgumentException e) {
                    // ============================================================
                    // HANDLE: Invalid token, malformed JWT, or parsing error
                    // Clear any existing authentication
                    // ============================================================
                    SecurityContextHolder.clearContext();

                } catch (Exception e) {
                    // ============================================================
                    // HANDLE: Any other unexpected error (database down, etc.)
                    // Clear any existing authentication
                    // ============================================================
                    SecurityContextHolder.clearContext();
                }
            }

        } catch (ExpiredJwtException e) {
            // ============================================================
            // HANDLE: Token expired (when extracting username)
            // ============================================================
            SecurityContextHolder.clearContext();

        } catch (JwtException | IllegalArgumentException e) {
            // ============================================================
            // HANDLE: Invalid token (when extracting username)
            // ============================================================
            SecurityContextHolder.clearContext();

        } catch (Exception e) {
            // ============================================================
            // HANDLE: Any other unexpected error
            // ============================================================
            SecurityContextHolder.clearContext();
        }

        // ============================================================
        // STEP 10: ALWAYS continue the filter chain
        // This ensures the request continues even if authentication fails
        // ============================================================
        filterChain.doFilter(request, response);
    }
}