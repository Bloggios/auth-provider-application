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

package com.bloggios.auth.provider.authentication;

import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.document.embedded.Role;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.authentication
 * Created_on - 10 December-2023
 * Created_at - 17 : 20
 */

@Getter
@Setter
@NoArgsConstructor
public class UserPrincipal implements OAuth2User, UserDetails {

    private String userId;
    private String username;
    private String email;
    private String password;
    private Boolean isEnabled;
    private Boolean isAccountNonExpired;
    private Boolean isAccountNonLocked;
    private Boolean isCredentialsNonExpired;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public UserPrincipal(
            String userId,
            String username,
            String email,
            String password,
            Boolean isEnabled,
            Boolean isAccountNonExpired,
            Boolean isAccountNonLocked,
            Boolean isCredentialsNonExpired,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.password = password;
        this.isEnabled = isEnabled;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
        this.authorities = authorities;
    }

    public static UserPrincipal create(UserDocument userAuth) {
        List<Role> roles = userAuth.getRoles();
        List<SimpleGrantedAuthority> collect = roles.stream().map(e -> new SimpleGrantedAuthority(e.getName())).toList();
        return new UserPrincipal(
                userAuth.getUserId(),
                userAuth.getUsername(),
                userAuth.getEmail(),
                userAuth.getPassword(),
                userAuth.isEnabled(),
                userAuth.isAccountNonExpired(),
                userAuth.isAccountNonLocked(),
                userAuth.isCredentialsNonExpired(),
                collect
        );
    }

    public static UserPrincipal create(UserDocument userAuth, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(userAuth);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return String.valueOf(userId);
    }
}
