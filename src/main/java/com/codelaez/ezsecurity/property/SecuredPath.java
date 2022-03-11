package com.codelaez.ezsecurity.property;

import lombok.Data;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import java.util.List;
import java.util.Objects;

/**
 * @author khanhspring
 */
@Data
@Validated
public class SecuredPath {
    @NotBlank
    private String pattern;
    private HttpMethod method;
    private Boolean permitAll;
    private List<String> authorities;

    public AntPathRequestMatcher requestMatcher() {
        if (Objects.isNull(this.getMethod())) {
            return new AntPathRequestMatcher(this.pattern);
        }
        return new AntPathRequestMatcher(this.pattern, this.method.name());
    }
}
