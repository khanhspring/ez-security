package com.codelaez.ezsecurity.configuration;

import com.codelaez.ezsecurity.property.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 * @author khanhspring
 */
@Order(2)
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = OAuth2Properties.PREFIX, name = "enable", havingValue = "true")
public class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2Properties oAuth2Properties;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .formLogin().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http = SecuredPathDefinition.http(http)
                .apply(oAuth2Properties.getSecuredPaths());

        http
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter);
    }

}
