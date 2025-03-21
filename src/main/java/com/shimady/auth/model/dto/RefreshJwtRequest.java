package com.shimady.auth.model.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RefreshJwtRequest {
    @NotEmpty(message = "refresh token cannot be blank")
    public String refreshToken;
}
