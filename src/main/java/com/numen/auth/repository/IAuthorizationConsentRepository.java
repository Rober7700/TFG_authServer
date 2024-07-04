package com.numen.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.numen.auth.entity.AuthorizationConsent;

import java.util.Optional;

@Repository
public interface IAuthorizationConsentRepository extends JpaRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {
	
	Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId,String principalName);

	void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}