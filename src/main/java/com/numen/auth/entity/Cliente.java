package com.numen.auth.entity;

import java.time.Duration;
import java.util.Date;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
@Table(name = "auth_clientes")
public class Cliente{
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String clienteId;
	
	private String clientSecret;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<ClientAuthenticationMethod> authenticationMethod;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<AuthorizationGrantType> authenticationGrandTypes;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<String> redirectUris;
	
	@ElementCollection(fetch = FetchType.EAGER)
	private Set<String> scopes;

	private boolean requiredProofKey;
	
	public static RegisteredClient toRegisteredClient(Cliente cliente){
        RegisteredClient.Builder builder = RegisteredClient.withId(cliente.getClienteId())
                .clientId(cliente.getClienteId())
                .clientSecret(cliente.getClientSecret())
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(am -> am.addAll(cliente.getAuthenticationMethod()))
                .authorizationGrantTypes(agt -> agt.addAll(cliente.getAuthenticationGrandTypes()))
                .redirectUris(ru -> ru.addAll(cliente.getRedirectUris()))
                .scopes(sc -> sc.addAll(cliente.getScopes()))
                .clientSettings(ClientSettings
                        .builder().requireProofKey(cliente.isRequiredProofKey()).requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(60))
                        .refreshTokenTimeToLive(Duration.ofHours(2))
                        .build());
        return builder.build();
	}
}
