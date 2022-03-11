package com.codelaez.ezsecurity.property;

import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import java.util.List;

/**
 * @author khanhspring
 */
@Data
@Validated
public class AuthUser {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
    private List<String> authorities;
}
