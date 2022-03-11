package com.codelaez.ezsecurity.configuration;

import com.codelaez.ezsecurity.property.SecuredPath;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Objects;

/**
 * @author khanhspring
 */
@AllArgsConstructor(staticName = "http")
public class SecuredPathDefinition {

    private HttpSecurity http;

    public HttpSecurity apply(List<SecuredPath> securedPaths) throws Exception {
        http = applyByPath(http, securedPaths);
        http = authorizeRequests(http, securedPaths);
        return http;
    }

    private HttpSecurity applyByPath(HttpSecurity http, List<SecuredPath> securedPaths) {
        if (ObjectUtils.isEmpty(securedPaths)) {
            return http;
        }
        var requestMatchers = http.requestMatchers();
        for (var path : securedPaths) {
            if (Objects.nonNull(path.getMethod())) {
                requestMatchers = requestMatchers.antMatchers(path.getMethod(), path.getPattern());
            } else {
                requestMatchers = requestMatchers.antMatchers(path.getPattern());
            }
        }
        return requestMatchers.and();
    }

    private HttpSecurity authorizeRequests(HttpSecurity http, List<SecuredPath> securedPaths) throws Exception {
        var authorizeRequests = http.authorizeRequests();
        if (ObjectUtils.isEmpty(securedPaths)) {
            authorizeRequests
                    .anyRequest()
                    .authenticated();
        }
        for (var path : securedPaths) {
            authorizeRequest(path, authorizeRequests);
        }
        return authorizeRequests.and();
    }

    private void authorizeRequest(SecuredPath path,
                                  ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests) {
        if (Boolean.TRUE.equals(path.getPermitAll())) {
            authorizeRequests
                    .requestMatchers(path.requestMatcher())
                    .permitAll();
            return;
        }

        if (ObjectUtils.isEmpty(path.getAuthorities())) {
            authorizeRequests
                    .requestMatchers(path.requestMatcher())
                    .authenticated();
            return;
        }

        authorizeRequests
                .requestMatchers(path.requestMatcher())
                .hasAnyAuthority(path.getAuthorities().toArray(new String[0]));

    }
}
