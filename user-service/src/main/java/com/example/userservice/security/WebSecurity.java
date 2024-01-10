package com.example.userservice.security;


import com.example.userservice.service.UserService;

import lombok.RequiredArgsConstructor;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurity{
    private final AuthenticationConfiguration authConfig;
    private final UserService userService;
    private final Environment env;

    @Bean
    public MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
//        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(AntPathRequestMatcher.antMatcher("/**")).permitAll());
        IpAddressMatcher hasIpv4 = new IpAddressMatcher("127.0.0.1");
        IpAddressMatcher hasIpv6 = new IpAddressMatcher("0:0:0:0:0:0:0:1");
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(mvc.pattern("/actuator/**")).permitAll());
        http.authorizeHttpRequests(authorize ->
                authorize.requestMatchers(mvc.pattern("/**"))
                        .access((authentication, object) ->
                                new AuthorizationDecision(hasIpv4.matches(object.getRequest()) || hasIpv6.matches(object.getRequest()))
                        )
        ).addFilter(getAuthenticationFilter());

        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        return http.build();
    }

    private AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationManager authenticationManager = authConfig.getAuthenticationManager();
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager,
                userService, env);
        return authenticationFilter;
    }
}
