package com.shimady.auth.model.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshJwtRequest {
    @NotEmpty(message = "refresh token cannot be blank")
    public String refreshToken;
}
