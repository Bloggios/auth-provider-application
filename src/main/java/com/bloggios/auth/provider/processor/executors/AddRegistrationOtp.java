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

package com.bloggios.auth.provider.processor.executors;

import com.bloggios.auth.provider.dao.repository.elasticsearch.EsRegistrationOtpRepository;
import com.bloggios.auth.provider.document.RegistrationOtpDocument;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.kafka.producer.producers.RegistrationOtpPayloadProducer;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.payload.event.OtpDataPayload;
import com.bloggios.auth.provider.utils.OtpGenerator;
import org.springframework.stereotype.Component;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.processor.executors
 * Created_on - 03 December-2023
 * Created_at - 00 : 07
 */

@Component
public class AddRegistrationOtp {

    private final OtpGenerator otpGenerator;
    private final EsRegistrationOtpRepository registrationOtpRepository;
    private final RegistrationOtpPayloadProducer registrationOtpPayloadProducer;

    public AddRegistrationOtp(
            OtpGenerator otpGenerator,
            EsRegistrationOtpRepository registrationOtpRepository,
            RegistrationOtpPayloadProducer registrationOtpPayloadProducer
    ) {
        this.otpGenerator = otpGenerator;
        this.registrationOtpRepository = registrationOtpRepository;
        this.registrationOtpPayloadProducer = registrationOtpPayloadProducer;
    }

    public void sendOtpMessage(UserEntity userAuth, Integer timesSent) {
        RegistrationOtpDocument registrationOtp = otpGenerator.registrationOtpSupplier(userAuth);
        registrationOtp.setTimesSent(timesSent);
        OtpDataPayload otpPayload = OtpDataPayload.builder().otp(registrationOtp.getOtp()).email(userAuth.getEmail()).build();
        registrationOtpPayloadProducer.sendMessage(otpPayload);
        registrationOtpRepository.save(registrationOtp);
    }

    public void sendOtpMessage(UserDocument userAuth, Integer timesSent) {
        RegistrationOtpDocument registrationOtp = otpGenerator.registrationOtpSupplier(userAuth);
        registrationOtp.setTimesSent(timesSent);
        OtpDataPayload otpPayload = OtpDataPayload.builder().otp(registrationOtp.getOtp()).email(userAuth.getEmail()).build();
        registrationOtpPayloadProducer.sendMessage(otpPayload);
        registrationOtpRepository.save(registrationOtp);
    }
}