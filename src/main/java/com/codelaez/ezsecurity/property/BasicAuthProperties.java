package com.codelaez.ezsecurity.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * @author khanhspring
 */
@Data
@Validated
@ConfigurationProperties(prefix = BasicAuthProperties.PREFIX)
public class BasicAuthProperties {
    public static final String PREFIX = "ez.security.basic-auth";

    private boolean enable;
    private List<AuthUser> users;
    private List<SecuredPath> securedPaths;
}
