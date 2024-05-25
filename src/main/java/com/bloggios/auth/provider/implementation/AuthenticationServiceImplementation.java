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

package com.bloggios.auth.provider.implementation;

import com.bloggios.auth.provider.authentication.CustomUserDetailService;
import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.constants.*;
import com.bloggios.auth.provider.dao.implementation.esimplementation.ForgetPasswordDao;
import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.UserEntityDao;
import com.bloggios.auth.provider.dao.repository.elasticsearch.EsRegistrationOtpRepository;
import com.bloggios.auth.provider.dao.repository.elasticsearch.UserDocumentRepository;
import com.bloggios.auth.provider.document.ForgetPasswordDocument;
import com.bloggios.auth.provider.document.RegistrationOtpDocument;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.enums.DaoStatus;
import com.bloggios.auth.provider.exception.payloads.AuthenticationException;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import com.bloggios.auth.provider.kafka.producer.producers.ForgetPasswordOtpProducer;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.payload.event.ForgetPasswordOtpEvent;
import com.bloggios.auth.provider.payload.record.RefreshTokenDaoValidationRecord;
import com.bloggios.auth.provider.payload.record.RemoteAddressResponse;
import com.bloggios.auth.provider.payload.request.AuthenticationRequest;
import com.bloggios.auth.provider.payload.request.ForgetPasswordRequest;
import com.bloggios.auth.provider.payload.request.RegisterRequest;
import com.bloggios.auth.provider.payload.response.AuthResponse;
import com.bloggios.auth.provider.payload.response.ModuleResponse;
import com.bloggios.auth.provider.persistence.RefreshTokenPersistence;
import com.bloggios.auth.provider.persistence.UserEntityToDocumentPersistence;
import com.bloggios.auth.provider.processor.elasticprocessor.EsUserAuthPersistProcessor;
import com.bloggios.auth.provider.processor.elasticprocessor.EsUserAuthUpdateProcessor;
import com.bloggios.auth.provider.processor.executors.AddRegistrationOtp;
import com.bloggios.auth.provider.processor.implementation.*;
import com.bloggios.auth.provider.service.AuthenticationService;
import com.bloggios.auth.provider.transformer.implementation.RegisterUserRequestToUserAuthTransformer;
import com.bloggios.auth.provider.utils.*;
import com.bloggios.auth.provider.validator.implementation.businessvalidator.NativeRefreshTokenValidator;
import com.bloggios.auth.provider.validator.implementation.businessvalidator.PasswordValidator;
import com.bloggios.auth.provider.validator.implementation.exhibitor.AuthenticationRequestValidator;
import com.bloggios.auth.provider.validator.implementation.exhibitor.ForgetPasswordUserAuthExhibitor;
import com.bloggios.auth.provider.validator.implementation.exhibitor.RegisterRequestExhibitor;
import com.bloggios.auth.provider.validator.implementation.exhibitor.ResendOtpExhibitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseCookie;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static com.bloggios.auth.provider.constants.BeanConstants.ASYNC_TASK_EXTERNAL_POOL;
import static com.bloggios.auth.provider.constants.ServiceConstants.ORIGIN;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.implementation
 * Created_on - 11 January-2024
 * Created_at - 20 : 38
 */

@Service
public class AuthenticationServiceImplementation implements AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImplementation.class);

    private final AuthenticationManager authenticationManager;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final AuthenticationRequestValidator authenticationRequestValidator;
    private final LoginDataProcessor loginDataProcessor;
    private final Environment environment;
    private final EsRegistrationOtpRepository registrationOtpRepository;
    private final UserDocumentRepository userAuthRepository;
    private final ResendOtpExhibitor resendOtpExhibitor;
    private final AddRegistrationOtp addRegistrationOtp;
    private final JwtDecoderUtil jwtDecoderUtil;
    private final JwtDecoder jwtDecoder;
    private final CustomUserDetailService customUserDetailService;
    private final PasswordEncoder passwordEncoder;
    private final PgSqlUserAuthPersistProcessor pgSqlUserAuthPersistProcessor;
    private final UserEventPublishProcessor userEventPublishProcessor;
    private final RegisterRequestExhibitor registerRequestExhibitor;
    private final RegisterUserRequestToUserAuthTransformer registerUserRequestToUserAuthTransformer;
    private final UserEntityDao userEntityDao;
    private final EsUserAuthPersistProcessor esUserAuthPersistProcessor;
    private final SendRegistrationOtpProcessor sendRegistrationOtpProcessor;
    private final ForgetPasswordUserAuthExhibitor forgetPasswordUserAuthExhibitor;
    private final ForgetPasswordDao forgetPasswordDao;
    private final OtpGenerator otpGenerator;
    private final ForgetPasswordOtpProducer forgetPasswordOtpProducer;
    private final PasswordValidator passwordValidator;
    private final EsUserAuthUpdateProcessor esUserAuthUpdateProcessor;
    private final RefreshTokenPersistence refreshTokenPersistence;
    private final VerifiedUserEntityTransformer verifiedUserEntityTransformer;
    private final UserEntityToDocumentPersistence userEntityToDocumentPersistence;
    private final LogoutUserRefreshTokenValidationProcessor logoutUserRefreshTokenValidationProcessor;
    private final NativeRefreshTokenValidator nativeRefreshTokenValidator;
    private final RefreshTokenDaoValidation refreshTokenDaoValidation;

    public AuthenticationServiceImplementation(
            AuthenticationManager authenticationManager,
            JwtTokenGenerator jwtTokenGenerator,
            AuthenticationRequestValidator authenticationRequestValidator,
            LoginDataProcessor loginDataProcessor,
            Environment environment,
            EsRegistrationOtpRepository registrationOtpRepository,
            UserDocumentRepository userAuthRepository,
            ResendOtpExhibitor resendOtpExhibitor,
            AddRegistrationOtp addRegistrationOtp,
            JwtDecoderUtil jwtDecoderUtil,
            JwtDecoder jwtDecoder,
            CustomUserDetailService customUserDetailService,
            PasswordEncoder passwordEncoder,
            PgSqlUserAuthPersistProcessor pgSqlUserAuthPersistProcessor,
            UserEventPublishProcessor userEventPublishProcessor,
            RegisterRequestExhibitor registerRequestExhibitor,
            RegisterUserRequestToUserAuthTransformer registerUserRequestToUserAuthTransformer,
            UserEntityDao userEntityDao,
            EsUserAuthPersistProcessor esUserAuthPersistProcessor,
            SendRegistrationOtpProcessor sendRegistrationOtpProcessor,
            ForgetPasswordUserAuthExhibitor forgetPasswordUserAuthExhibitor,
            ForgetPasswordDao forgetPasswordDao,
            OtpGenerator otpGenerator,
            ForgetPasswordOtpProducer forgetPasswordOtpProducer,
            PasswordValidator passwordValidator,
            EsUserAuthUpdateProcessor esUserAuthUpdateProcessor,
            RefreshTokenPersistence refreshTokenPersistence,
            VerifiedUserEntityTransformer verifiedUserEntityTransformer,
            UserEntityToDocumentPersistence userEntityToDocumentPersistence,
            LogoutUserRefreshTokenValidationProcessor logoutUserRefreshTokenValidationProcessor,
            NativeRefreshTokenValidator nativeRefreshTokenValidator,
            RefreshTokenDaoValidation refreshTokenDaoValidation
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenGenerator = jwtTokenGenerator;
        this.authenticationRequestValidator = authenticationRequestValidator;
        this.loginDataProcessor = loginDataProcessor;
        this.environment = environment;
        this.registrationOtpRepository = registrationOtpRepository;
        this.userAuthRepository = userAuthRepository;
        this.resendOtpExhibitor = resendOtpExhibitor;
        this.addRegistrationOtp = addRegistrationOtp;
        this.jwtDecoderUtil = jwtDecoderUtil;
        this.jwtDecoder = jwtDecoder;
        this.customUserDetailService = customUserDetailService;
        this.passwordEncoder = passwordEncoder;
        this.pgSqlUserAuthPersistProcessor = pgSqlUserAuthPersistProcessor;
        this.userEventPublishProcessor = userEventPublishProcessor;
        this.registerRequestExhibitor = registerRequestExhibitor;
        this.registerUserRequestToUserAuthTransformer = registerUserRequestToUserAuthTransformer;
        this.userEntityDao = userEntityDao;
        this.esUserAuthPersistProcessor = esUserAuthPersistProcessor;
        this.sendRegistrationOtpProcessor = sendRegistrationOtpProcessor;
        this.forgetPasswordUserAuthExhibitor = forgetPasswordUserAuthExhibitor;
        this.forgetPasswordDao = forgetPasswordDao;
        this.otpGenerator = otpGenerator;
        this.forgetPasswordOtpProducer = forgetPasswordOtpProducer;
        this.passwordValidator = passwordValidator;
        this.esUserAuthUpdateProcessor = esUserAuthUpdateProcessor;
        this.refreshTokenPersistence = refreshTokenPersistence;
        this.verifiedUserEntityTransformer = verifiedUserEntityTransformer;
        this.userEntityToDocumentPersistence = userEntityToDocumentPersistence;
        this.logoutUserRefreshTokenValidationProcessor = logoutUserRefreshTokenValidationProcessor;
        this.nativeRefreshTokenValidator = nativeRefreshTokenValidator;
        this.refreshTokenDaoValidation = refreshTokenDaoValidation;
    }

    /**
     * Register User
     *
     * @param request
     * @param httpServletRequest
     * @return
     */
    @Override
    @Transactional
    @Async(ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<ModuleResponse> registerUser(RegisterRequest request, HttpServletRequest httpServletRequest) {
        long startTime = System.currentTimeMillis();
        registerRequestExhibitor.validate(request);
        UserEntity userEntity = registerUserRequestToUserAuthTransformer.transform(request, httpServletRequest);
        UserEntity response = userEntityDao.initOperation(DaoStatus.CREATE, userEntity);
        esUserAuthPersistProcessor.persistData(response);
        CompletableFuture.runAsync(() -> sendRegistrationOtpProcessor.process(response));
        logger.info("Execution Time (Register User) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(ModuleResponse
                .builder()
                .message(ResponseMessageConstants.USER_REGISTERED)
                .userId(response.getUserId())
                .build());
    }

    /**
     * Login User
     *
     * @param authenticationRequest
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<AuthResponse> authenticate(AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        long startTime = System.currentTimeMillis();
        authenticationRequestValidator.validate(authenticationRequest);
        Authentication userAuthentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEntrypoint(),
                        authenticationRequest.getPassword()
                )
        );
        loginDataProcessor.validateOrigins(userAuthentication, httpServletRequest);
        AuthResponse authResponse = getAuthResponse(httpServletRequest, userAuthentication);
        logger.info("Execution Time (Login User) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(authResponse);
    }

    /**
     *
     * Verify OTP
     * @param otp
     * @param userId
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    @Transactional
    public CompletableFuture<ModuleResponse> verifyOtp(String otp, String userId) {
        long startTime = System.currentTimeMillis();
        ValueCheckerUtil.isValidUUID(userId);
        Optional<RegistrationOtpDocument> byUserIdOptional = registrationOtpRepository.findByUserId(userId);
        if (byUserIdOptional.isEmpty()) {
            throw new BadRequestException(ExceptionCodes.USER_NOT_PRESENT_FOR_OTP);
        }
        UserEntity userEntity = userEntityDao.findById(userId)
                .orElseThrow(() -> new BadRequestException(ExceptionCodes.USER_NOT_FOUND));
        RegistrationOtpDocument registrationOtpDocument = byUserIdOptional.get();
        if (!registrationOtpDocument.getOtp().equals(otp)) {
            throw new BadRequestException(ExceptionCodes.OTP_NOT_VALID);
        }
        if (Boolean.TRUE.equals(userEntity.isEnabled()))
            throw new BadRequestException(ExceptionCodes.USER_ALREADY_ENABLED);
        if (registrationOtpDocument.getExpiry().before(new Date()))
            throw new BadRequestException(ExceptionCodes.EXPIRED_OTP);
        UserEntity transform = verifiedUserEntityTransformer.transform(userEntity);
        UserEntity response = userEntityDao.initOperation(DaoStatus.UPDATE, transform);
        CompletableFuture.runAsync(()-> userEntityToDocumentPersistence.persist(response, DaoStatus.UPDATE));
        CompletableFuture.runAsync(()-> registrationOtpRepository.deleteById(registrationOtpDocument.getOtpId()));
        CompletableFuture.runAsync(() -> userEventPublishProcessor.process(response));
        logger.info("Execution Time (Verify OTP) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(ModuleResponse
                .builder()
                .message(ResponseMessageConstants.USER_VERIFIED_SUCCESSFULLY)
                .userId(userId)
                .build());
    }

    /**
     *
     * Resend OTP
     * @param userId
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<ModuleResponse> resendOtp(String userId) {
        long startTime = System.currentTimeMillis();
        CompletableFuture<Optional<RegistrationOtpDocument>> registrationOtpOptionalCompletableFuture = CompletableFuture.supplyAsync(() -> registrationOtpRepository.findByUserId(userId));
        CompletableFuture<Optional<UserDocument>> optionalCompletableFuture = CompletableFuture.supplyAsync(() -> userAuthRepository.findById(userId));
        CompletableFuture.allOf(registrationOtpOptionalCompletableFuture, optionalCompletableFuture).join();
        Optional<RegistrationOtpDocument> registrationOtpOptional = registrationOtpOptionalCompletableFuture.join();
        Optional<UserDocument> userAuthOptional = optionalCompletableFuture.join();
        if (registrationOtpOptional.isEmpty()) throw new BadRequestException(ExceptionCodes.OTP_NOT_PRESENT_FOR_USER);
        if (userAuthOptional.isEmpty()) throw new BadRequestException(ExceptionCodes.USER_NOT_FOUND);
        RegistrationOtpDocument registrationOtp = registrationOtpOptional.get();
        resendOtpExhibitor.validate(registrationOtp, userAuthOptional.get());
        registrationOtpRepository.delete(registrationOtp);
        CompletableFuture.runAsync(() -> addRegistrationOtp.sendOtpMessage(userAuthOptional.get(), registrationOtp.getTimesSent() + 1));
        logger.info("Execution Time (Resend OTP) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(ModuleResponse
                .builder()
                .message(ResponseMessageConstants.OTP_RESEND_SUCCESSFULLY)
                .build());
    }

    /**
     *
     * Logout User
     * @param request
     * @param response
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<AuthResponse> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        long startTime = System.currentTimeMillis();
        Cookie[] cookies = request.getCookies();
        if (cookies == null) throw new BadRequestException(ExceptionCodes.USER_ALREADY_LOGGED_OUT);
        String cookieName = environment.getProperty(EnvironmentConstants.REFRESH_TOKEN_COOKIE_NAME);
        Optional<Cookie> refreshTokenCookie = CookieUtils.getCookie(request, cookieName);
        CompletableFuture.runAsync(()-> logoutUserRefreshTokenValidationProcessor.process(refreshTokenCookie, request));
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(1);
        cookie.setPath("/");
        logger.info("Execution Time (Logout User) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(AuthResponse.builder().build());
    }

    /**
     *
     * Refresh Token
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<AuthResponse> refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        long startTime = System.currentTimeMillis();
        String cookieName = environment.getProperty(EnvironmentConstants.REFRESH_TOKEN_COOKIE_NAME);
        Cookie[] cookies = httpServletRequest.getCookies();
        if (Objects.isNull(cookies)) throw new AuthenticationException(ExceptionCodes.LOGIN_AGAIN);
        Optional<Cookie> refreshTokenOptional = CookieUtils.getCookie(httpServletRequest, cookieName);
        if (refreshTokenOptional.isEmpty()) throw new AuthenticationException(ExceptionCodes.LOGIN_AGAIN);
        String refreshToken = refreshTokenOptional.get().getValue();
        UsernamePasswordAuthenticationToken authentication = getAuthenticationForRefreshToken(refreshToken, httpServletRequest);
        AuthResponse authResponse = getAuthResponse(httpServletRequest, authentication);
        logger.info("Execution Time (Refresh Token) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(authResponse);
    }

    /**
     *
     * User Id for OTP Redirect
     * @param authenticationRequest
     * @return
     */
    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<ModuleResponse> otpRedirectUserId(AuthenticationRequest authenticationRequest) {
        long startTime = System.currentTimeMillis();
        Optional<UserDocument> byEmail = userAuthRepository.findByEmail(authenticationRequest.getEntrypoint());
        if (byEmail.isEmpty()) throw new AuthenticationException(ExceptionCodes.USER_NOT_FOUND_WITH_EMAIL);
        UserDocument userAuth = byEmail.get();
        if (!passwordEncoder.matches(authenticationRequest.getPassword(), userAuth.getPassword()))
            throw new AuthenticationException(ExceptionCodes.INCORRECT_PASSWORD);
        logger.info("Execution Time (OTP Redirect User Id) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(ModuleResponse
                .builder()
                .message(ResponseMessageConstants.OTP_REDIRECT_USER_ID)
                .userId(userAuth.getUserId())
                .build());
    }

    /**
     *
     * Refresh Access Token Social
     * @param token
     * @param httpServletResponse
     * @param httpServletRequest
     * @return
     */
    @Override
    public CompletableFuture<AuthResponse> refreshTokenSocial(String token, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) {
        long startTime = System.currentTimeMillis();
        if (token.isEmpty()) throw new AuthenticationException(ExceptionCodes.LOGIN_AGAIN);
        UsernamePasswordAuthenticationToken authentication = getAuthenticationForRefreshToken(token, httpServletRequest);
        AuthResponse authResponse = getAuthResponse(httpServletRequest, authentication);
        logger.info("Execution Time (Social Refresh Token) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(authResponse);
    }

    /**
     *
     * Forget Password OTP Send
     * @param email
     * @return
     */
    @Override
    public CompletableFuture<ModuleResponse> forgetPasswordOtp(String email) {
        long startTime = System.currentTimeMillis();
        CompletableFuture<UserEntity> usetAuthEntityCompletableFuture = CompletableFuture.supplyAsync(() -> userEntityDao.findByEmail(email));
        CompletableFuture<Optional<ForgetPasswordDocument>> optionalCompletableFuture = CompletableFuture.supplyAsync(() -> forgetPasswordDao.findByEmail(email));
        AsyncUtils.getAsyncResult(CompletableFuture.allOf(usetAuthEntityCompletableFuture, optionalCompletableFuture));
        UserEntity userAuth = usetAuthEntityCompletableFuture.join();
        Optional<ForgetPasswordDocument> forgetPasswordDocument = optionalCompletableFuture.join();
        forgetPasswordUserAuthExhibitor.validate(userAuth);
        forgetPasswordDocument.ifPresent(document -> {
            if (document.getUserId().equals(userAuth.getUserId()))
                CompletableFuture.runAsync(() -> forgetPasswordDao.delete(document));
            else throw new BadRequestException(ExceptionCodes.FORGET_PASSWORD_USER_ID_NOT_MATCHED_EMAIL_USER_AUTH);
        });
        ForgetPasswordDocument forgetPassword = otpGenerator.forgetPasswordOtpSupplier(userAuth);
        ForgetPasswordDocument response = forgetPasswordDao.initOperation(DaoStatus.CREATE, forgetPassword);
        ForgetPasswordOtpEvent otpEvent = ForgetPasswordOtpEvent.builder().email(response.getEmail()).otp(response.getOtp()).build();
        CompletableFuture.runAsync(() -> forgetPasswordOtpProducer.sendMessage(otpEvent));
        logger.info("Execution Time (Forget Password OTP Send) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(
                ModuleResponse
                        .builder()
                        .message(ResponseMessageConstants.FORGET_PASSWORD_OTP_SENT)
                        .userId(response.getUserId())
                        .id(response.getOtpId())
                        .build()
        );
    }

    /**
     *
     * Forget Password
     * @param forgetPasswordRequest
     * @return
     */
    @Override
    public CompletableFuture<ModuleResponse> forgetPassword(ForgetPasswordRequest forgetPasswordRequest) {
        long startTime = System.currentTimeMillis();
        String userId = forgetPasswordRequest.getUserId();
        ValueCheckerUtil.isValidUUID(userId, ExceptionCodes.INVALID_USER_ID);
        CompletableFuture<ForgetPasswordDocument> forgetPasswordDocumentCompletableFuture = CompletableFuture.supplyAsync(() -> forgetPasswordDao.findByUserId(userId));
        CompletableFuture<UserEntity> userAuthEntityCompletableFuture = CompletableFuture.supplyAsync(() -> userEntityDao.findUserById(userId));
        AsyncUtils.getAsyncResult(CompletableFuture.allOf(forgetPasswordDocumentCompletableFuture, userAuthEntityCompletableFuture));
        ForgetPasswordDocument byUserId = forgetPasswordDocumentCompletableFuture.join();
        UserEntity userById = userAuthEntityCompletableFuture.join();
        if (!byUserId.getOtp().equals(forgetPasswordRequest.getOtp()))
            throw new AuthenticationException(ExceptionCodes.INVALID_FORGET_PASSWORD_OTP);
        passwordValidator.validate(forgetPasswordRequest.getNewPassword());
        userById.setPassword(passwordEncoder.encode(forgetPasswordRequest.getNewPassword()));
        userById.setLastPasswordChanged(new Date());
        UserEntity userEntity = userEntityDao.initOperation(DaoStatus.UPDATE, userById);
        esUserAuthUpdateProcessor.process(userEntity);
        CompletableFuture.runAsync(() -> forgetPasswordDao.delete(byUserId));
        logger.info("Execution Time (Forget Password) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(
                ModuleResponse
                        .builder()
                        .message(ResponseMessageConstants.PASSWORD_CHANGED)
                        .userId(userId)
                        .build()
        );
    }

    /**
     *
     * Remote Address
     * @param request
     * @return
     */
    @Override
    public CompletableFuture<RemoteAddressResponse> remoteAddress(HttpServletRequest request) {
        long startTime = System.currentTimeMillis();
        String v4 = IpUtils.getRemoteAddress(request);
        String localAddr = request.getLocalAddr();
        logger.info("Execution Time (Remote Address) -> {}ms", System.currentTimeMillis() - startTime);
        return CompletableFuture.completedFuture(
                new RemoteAddressResponse(v4, localAddr)
        );
    }

    private String getOrigin(HttpServletRequest httpServletRequest) {
        String origin = httpServletRequest.getHeader(ORIGIN);
        if (ObjectUtils.isEmpty(httpServletRequest.getHeader(ORIGIN))) {
            origin = ServiceConstants.LOCAL_ORIGIN;
        }
        return origin;
    }

    private boolean isLongToken(HttpServletRequest httpServletRequest) {
        String origin = httpServletRequest.getHeader(ORIGIN);
        return ObjectUtils.isEmpty(origin);
    }

    private AuthResponse getAuthResponse(HttpServletRequest httpServletRequest, Authentication userAuthentication) {
        UserPrincipal principal = (UserPrincipal) userAuthentication.getPrincipal();
        String remoteAddress = IpUtils.getRemoteAddress(httpServletRequest);
        String cookieName = environment.getProperty(EnvironmentConstants.REFRESH_TOKEN_COOKIE_NAME);
        String accessToken = jwtTokenGenerator.generateAccessToken(
                userAuthentication,
                getOrigin(httpServletRequest),
                isLongToken(httpServletRequest),
                remoteAddress
        );
        String refreshToken = jwtTokenGenerator.generateRefreshToken(
                userAuthentication,
                getOrigin(httpServletRequest),
                remoteAddress
        );
        SecurityContextHolder.getContext().setAuthentication(userAuthentication);
        AuthResponse authResponse = AuthResponse.builder()
                .userId(principal.getUserId())
                .accessToken(accessToken)
                .remoteAddress(IpUtils.getRemoteAddress(httpServletRequest))
                .email(principal.getEmail())
                .username(principal.getUsername())
                .authorities(userAuthentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();
        CompletableFuture.runAsync(() -> refreshTokenPersistence.persist(
                refreshToken,
                accessToken,
                principal,
                remoteAddress
        ));
        if (Objects.nonNull(refreshToken)) {
            String origin = httpServletRequest.getHeader(ORIGIN);
            assert cookieName != null;
            ResponseCookie cookie = ResponseCookie
                    .from(cookieName, refreshToken)
                    .httpOnly(!origin.contains("localhost:"))
                    .maxAge(86400)
                    .path("/")
                    .sameSite("None")
                    .secure(true)
                    .build();
            authResponse.setCookie(cookie);
        }
        return authResponse;
    }

    private UsernamePasswordAuthenticationToken getAuthenticationForRefreshToken(String token, HttpServletRequest httpServletRequest) {
        CompletableFuture<Void> nativeValidationFuture = CompletableFuture.runAsync(() -> nativeRefreshTokenValidator.validate(token));
        CompletableFuture<Object> daoValidationFuture = CompletableFuture.supplyAsync(() -> refreshTokenDaoValidation.validate(token, httpServletRequest));
        AsyncUtils.getAsyncResult(CompletableFuture.allOf(nativeValidationFuture, daoValidationFuture));
        Object daoValidation = daoValidationFuture.join();
        if (daoValidation instanceof RefreshTokenDaoValidationRecord record) {
            CompletableFuture.completedFuture(
                    AuthResponse
                            .builder()
//                            .cookie(record.cookie())
                            .message(record.message())
                            .build()
            );
        }
        String userId = jwtDecoderUtil.extractUserId(token);
        UserDetails userDetails = customUserDetailService.loadUserById(userId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        return authentication;
    }
}
