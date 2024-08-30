/*
 * Copyright © 2023-2024 Bloggios
 * All rights reserved.
 * This software is the property of Rohit Parihar and is protected by copyright law.
 * The software, including its source code, documentation, and associated files, may not be used, copied, modified, distributed, or sublicensed without the express written consent of Rohit Parihar.
 * For licensing and usage inquiries, please contact Rohit Parihar at rohitparih@gmail.com, or you can also contact support@bloggios.com.
 * This software is provided as-is, and no warranties or guarantees are made regarding its fitness for any particular purpose or compatibility with any specific technology.
 * For license information and terms of use, please refer to the accompanying LICENSE file or visit http://www.apache.org/licenses/LICENSE-2.0.
 * Unauthorized use of this software may result in legal action and liability for damages.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bloggios.auth.provider.configuration;

import com.bloggios.auth.provider.authentication.BloggiosAuthenticationEntryPoint;
import com.bloggios.auth.provider.authentication.BloggiosAuthenticationProvider;
import com.bloggios.auth.provider.authentication.CustomUserDetailService;
import com.bloggios.auth.provider.authentication.JwtTokenValidationFilter;
import com.bloggios.auth.provider.properties.AuthenticationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.configuration
 * Created_on - 09 December-2023
 * Created_at - 23 : 47
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final AuthenticationProperties authenticationProperties;
    private final CustomUserDetailService customUserDetailService;
    private final BloggiosAuthenticationEntryPoint bloggiosAuthenticationEntryPoint;
    private final JwtTokenValidationFilter jwtTokenValidationFilter;

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        List<String> paths = authenticationProperties.getPathExclude().getPaths();
        String[] pathArray = new String[paths.size()];
        paths.toArray(pathArray);
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> {
                    auth
                            .antMatchers(pathArray).permitAll()
                            .anyRequest().authenticated();
                })
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(e -> {
                    e.authenticationEntryPoint(
                            bloggiosAuthenticationEntryPoint
                    );
                    e.accessDeniedHandler(
                            (request, response, accessDeniedException) -> response.sendError(HttpServletResponse.SC_FORBIDDEN)
                    );
                })
                .formLogin().disable()
                .httpBasic().disable();
        http.addFilterBefore(jwtTokenValidationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public BloggiosAuthenticationProvider bloggiosAuthenticationProvider() {
        BloggiosAuthenticationProvider authenticationProvider = new BloggiosAuthenticationProvider();
        authenticationProvider.setUserDetailsService(customUserDetailService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return authentication -> bloggiosAuthenticationProvider().authenticate(authentication);
    }
}
