package com.shimady.auth.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtRequest {
    // TODO: Add validation
    private String email;
    private String password;
}
