package com.shimady.auth.model.dto;

import com.shimady.auth.validation.Password;
import jakarta.validation.constraints.Email;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class JwtRequest {
    @Email(regexp = "^[a-zA-Z0-9_!#$%&’*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$",
            message = "wrong format of email")
    private String email;

    @Password(message = "password should be at least 8 characters long " +
            "and contain at least one lower case letter, " +
            "upper case letter, " +
            "digit, " +
            "symbol from @#$%^&+=")
    private String password;
}
