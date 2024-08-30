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

package com.bloggios.auth.provider.controller;

import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.constants.EndpointConstants;
import com.bloggios.auth.provider.payload.request.AssignRoleRequest;
import com.bloggios.auth.provider.payload.request.ChangePasswordRequest;
import com.bloggios.auth.provider.payload.response.ExceptionResponse;
import com.bloggios.auth.provider.payload.response.ModuleResponse;
import com.bloggios.auth.provider.payload.response.UserAuthResponse;
import com.bloggios.auth.provider.payload.response.UserProfileResponse;
import com.bloggios.auth.provider.service.UserService;
import com.bloggios.auth.provider.utils.AsyncUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.controller
 * Created_on - 11 January-2024
 * Created_at - 21 : 08
 */

@RestController
@RequestMapping(EndpointConstants.USER_READ_BASE_PATH)
public class UserController {

    private final UserService userService;

    public UserController(
            UserService userService
    ) {
        this.userService = userService;
    }

    @GetMapping
    @Operation(
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = false
            ),
            responses = {
                    @ApiResponse(description = "SUCCESS", responseCode = "200", content = @Content(
                            mediaType = "application/json", schema = @Schema(implementation = UserAuthResponse.class)
                    )),
                    @ApiResponse(description = "No Content", responseCode = "401", content = {
                            @Content(schema = @Schema(implementation = Void.class))
                    }),
                    @ApiResponse(description = "FORBIDDEN", responseCode = "403", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))
                    }),
                    @ApiResponse(description = "BAD REQUEST", responseCode = "400", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = ExceptionResponse.class))
                    })
            },
            security = {
                    @SecurityRequirement(
                            name = "bearerAuth"
                    )
            }
    )
    public ResponseEntity<UserAuthResponse> getLoggedInUser(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(userService.getLoggedInUser(userPrincipal)));
    }

    @PostMapping(EndpointConstants.UserController.CHANGE_PASSWORD)
    @Operation(
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = false
            ),
            responses = {
                    @ApiResponse(description = "SUCCESS", responseCode = "200", content = @Content(
                            mediaType = "application/json", schema = @Schema(implementation = ModuleResponse.class)
                    )),
                    @ApiResponse(description = "No Content", responseCode = "401", content = {
                            @Content(schema = @Schema(implementation = Void.class))
                    }),
                    @ApiResponse(description = "FORBIDDEN", responseCode = "403", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))
                    }),
                    @ApiResponse(description = "BAD REQUEST", responseCode = "400", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = ExceptionResponse.class))
                    })
            },
            security = {
                    @SecurityRequirement(
                            name = "bearerAuth"
                    )
            }
    )
    public ResponseEntity<ModuleResponse> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, @AuthenticationPrincipal UserPrincipal userPrincipal) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(userService.changePassword(changePasswordRequest, userPrincipal)));
    }

    @PostMapping(EndpointConstants.UserController.ASSIGN_ROLES)
    @Operation(
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = false
            ),
            responses = {
                    @ApiResponse(description = "SUCCESS", responseCode = "200", content = @Content(
                            mediaType = "application/json", schema = @Schema(implementation = ModuleResponse.class)
                    )),
                    @ApiResponse(description = "No Content", responseCode = "401", content = {
                            @Content(schema = @Schema(implementation = Void.class))
                    }),
                    @ApiResponse(description = "FORBIDDEN", responseCode = "403", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))
                    }),
                    @ApiResponse(description = "BAD REQUEST", responseCode = "400", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = ExceptionResponse.class))
                    })
            },
            security = {
                    @SecurityRequirement(
                            name = "bearerAuth"
                    )
            }
    )
    public ResponseEntity<ModuleResponse> assignRole(@RequestBody AssignRoleRequest assignRoleRequest, @AuthenticationPrincipal UserPrincipal authenticatedUser) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(userService.assignRoles(assignRoleRequest, authenticatedUser)));
    }


    @GetMapping(EndpointConstants.UserController.GET_USER_PROFILE_RESPONSE)
    @Operation(
            summary = "This API is developed for Inter Communication between Microservices",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = false
            ),
            responses = {
                    @ApiResponse(description = "SUCCESS", responseCode = "200", content = @Content(
                            mediaType = "application/json", schema = @Schema(implementation = UserProfileResponse.class)
                    )),
                    @ApiResponse(description = "No Content", responseCode = "401", content = {
                            @Content(schema = @Schema(implementation = Void.class))
                    }),
                    @ApiResponse(description = "FORBIDDEN", responseCode = "403", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))
                    }),
                    @ApiResponse(description = "BAD REQUEST", responseCode = "400", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = ExceptionResponse.class))
                    })
            },
            security = {
                    @SecurityRequirement(
                            name = "bearerAuth"
                    )
            }
    )
    public ResponseEntity<UserProfileResponse> getUserProfileResponse(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(userService.getUserProfileResponse(userPrincipal)));
    }
}
