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
@ConfigurationProperties(prefix = OAuth2Properties.PREFIX)
public class OAuth2Properties {
    public static final String PREFIX = "ez.security.oauth2";

    private boolean enable;
    private List<SecuredPath> securedPaths;
    private String authorityPrefix;
    private String authorityClaimName;

}
