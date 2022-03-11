package com.codelaez.ezsecurity.configuration;

import com.codelaez.ezsecurity.property.BasicAuthProperties;
import com.codelaez.ezsecurity.property.SecuredPath;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;

import java.util.Objects;

/**
 * @author khanhspring
 */
@Order(1)
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = BasicAuthProperties.PREFIX, name = "enable", havingValue = "true")
public class BasicAuthSecurityConfig extends WebSecurityConfigurerAdapter {

    private final BasicAuthProperties basicAuthProperties;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        if (ObjectUtils.isEmpty(basicAuthProperties.getUsers())) {
            return;
        }
        var inMemoryAuth = auth.inMemoryAuthentication();
        for (var user : basicAuthProperties.getUsers()) {
            var inMemoryUser = inMemoryAuth
                    .withUser(user.getUsername())
                    .password(passwordEncoder.encode(user.getPassword()));
            if (!ObjectUtils.isEmpty(user.getAuthorities())) {
                inMemoryUser.authorities(user.getAuthorities().toArray(new String[0]));
            }
            inMemoryAuth = inMemoryUser.and();
        }
    }

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
                .apply(basicAuthProperties.getSecuredPaths());
        http.httpBasic();
    }

}
