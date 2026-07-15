package com.ilango.Security_project.dto;

import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank
    @Size(min = 3, max = 30)
    private String username;


    @Email
    @NotBlank
    private String email;


    @NotBlank
    @Size(min = 8)
    private String password;
}
