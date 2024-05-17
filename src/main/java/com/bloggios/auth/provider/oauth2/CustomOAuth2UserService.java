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

package com.bloggios.auth.provider.oauth2;

import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.dao.implementation.esimplementation.UserDocumentDao;
import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.UserEntityDao;
import com.bloggios.auth.provider.dao.repository.postgres.PgSqlRoleRepository;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.enums.DaoStatus;
import com.bloggios.auth.provider.enums.Provider;
import com.bloggios.auth.provider.exception.payloads.OAuth2AuthenticationProcessingException;
import com.bloggios.auth.provider.modal.RoleEntity;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.processor.elasticprocessor.EsUserAuthPersistProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import static com.bloggios.auth.provider.constants.EnvironmentConstants.APPLICATION_VERSION;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.oauth2
 * Created_on - 07 February-2024
 * Created_at - 18 : 10
 */

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserEntityDao userEntityDao;
    private final PgSqlRoleRepository roleRepository;
    private final Environment environment;
    private final EsUserAuthPersistProcessor esUserAuthPersistProcessor;
    private final UserDocumentDao userDocumentDao;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }
        Optional<UserEntity> userOptional = userEntityDao.findByEmailOptional(oAuth2UserInfo.getEmail());
        UserEntity auth;
        UserDocument authDocument;
        if(userOptional.isPresent()) {
            auth = userOptional.get();
            if(!auth.getProvider().equals(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        auth.getProvider() + " account. Please use your " + auth.getProvider() +
                        " account to login.");
            }
            authDocument = userDocumentDao.findById(auth.getUserId());
        } else {
            authDocument = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(authDocument, oAuth2User.getAttributes());
    }

    private UserDocument registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        UserEntity auth = new UserEntity();
        auth.setProvider(Provider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        auth.setProviderId(oAuth2UserInfo.getId());
        auth.setEmail(oAuth2UserInfo.getEmail());
        auth.setDateRegistered(new Date());
        auth.setEnabled(true);
        auth.setAccountNonExpired(true);
        auth.setCredentialsNonExpired(true);
        auth.setAccountNonLocked(true);
        auth.setVersion(environment.getProperty(APPLICATION_VERSION));
        RoleEntity role = this.roleRepository.findById("user").get();
        auth.setRoles(List.of(role));
        UserEntity userEntity = userEntityDao.initOperation(DaoStatus.CREATE, auth);
//        assignRole(userAuthEntity.getUserId());
        return esUserAuthPersistProcessor.persistData(userEntity);
    }

//    public void assignRole(String userid){
//        Role role = this.roleRepository.findById("social").get();
//        Auth auth = this.authRepository.findById(userid).get();
//        auth.setRoles(List.of(role));
//        authRepository.save(auth);
//    }
}

