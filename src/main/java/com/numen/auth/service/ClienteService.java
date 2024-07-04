package com.numen.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import com.numen.auth.dto.CreateClienteDto;
import com.numen.auth.dto.MensajeDto;
import com.numen.auth.entity.Cliente;
import com.numen.auth.repository.IClienteRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ClienteService implements RegisteredClientRepository{

	@Autowired
	private IClienteRepository clienteRepository;
    private final PasswordEncoder passwordEncoder;
	

	@Override
	public void save(RegisteredClient registeredClient) {
		
	}

	@Override
	public RegisteredClient findById(String id) {
		Cliente client = clienteRepository.findByClienteId(id)
				.orElseThrow(() -> new RuntimeException("cliente not found"));
		return Cliente.toRegisteredClient(client);
	}
    
	@Override
    public RegisteredClient findByClientId(String clientId) {
        Cliente client = clienteRepository.findByClienteId(clientId)
                .orElseThrow(()-> new RuntimeException("El cliente: " + clientId + " = not found"));
        return Cliente.toRegisteredClient(client);
    }

    public MensajeDto create(CreateClienteDto dto){
        Cliente client = clientFromDto(dto);
        clienteRepository.save(client);
        return new MensajeDto("cliente " + client.getClienteId() + " guardado");
    }

    // private methods
    private Cliente clientFromDto(CreateClienteDto dto){
        Cliente client = Cliente.builder()
                .clienteId(dto.getClienteId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethod(dto.getAuthenticationMethod())
                .authenticationGrandTypes(dto.getAuthenticationGrandTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requiredProofKey(dto.isRequiredProofKey())
                .build();
        return client;
    }

}
