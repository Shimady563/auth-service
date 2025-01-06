package com.shimady.auth.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshJwtRequest {
    public String refreshToken;
}
