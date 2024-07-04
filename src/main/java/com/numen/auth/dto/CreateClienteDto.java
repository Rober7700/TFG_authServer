package com.numen.auth.dto;

import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateClienteDto {

	private String clienteId;
	private String clientSecret;
	private Set<ClientAuthenticationMethod> authenticationMethod;
	private Set<AuthorizationGrantType> authenticationGrandTypes;
	private Set<String> redirectUris;
	private Set<String> scopes;
	private boolean requiredProofKey;

}
