package com.codelaez.ezsecurity;

import com.codelaez.ezsecurity.property.BasicAuthProperties;
import com.codelaez.ezsecurity.property.OAuth2Properties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Objects;

@Configuration
@EnableConfigurationProperties({
        BasicAuthProperties.class,
        OAuth2Properties.class
})
public class EzSecurityAutoConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = BasicAuthProperties.PREFIX, name = "enable", havingValue = "true")
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
    public JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
        return NimbusJwtDecoder
                .withJwkSetUri(properties.getJwt().getJwkSetUri())
                .build();
    }

    @Bean
    @ConditionalOnProperty(prefix = OAuth2Properties.PREFIX, name = "enable", havingValue = "true")
    public JwtAuthenticationConverter jwtAuthenticationConverter(OAuth2Properties properties) {
        var grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        if (Objects.nonNull(properties.getAuthorityClaimName())) {
            grantedAuthoritiesConverter.setAuthoritiesClaimName(properties.getAuthorityClaimName());
        }
        if (Objects.nonNull(properties.getAuthorityPrefix())) {
            grantedAuthoritiesConverter.setAuthorityPrefix(properties.getAuthorityPrefix());
        }

        var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
