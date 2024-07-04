package com.numen.auth.federated;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.numen.auth.entity.GoogleUser;
import com.numen.auth.repository.IGoogleUserRepository;

import lombok.RequiredArgsConstructor;

import java.util.function.Consumer;

@RequiredArgsConstructor
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

	private final Logger LOG = LoggerFactory.getLogger(UserRepositoryOAuth2UserHandler.class);
	
	private final IGoogleUserRepository googleUserRepository;
	
	@Override
	public void accept(OAuth2User user) {
		// Capture user in a local data store on first authentication
        if (!this.googleUserRepository.findByEmail(user.getName()).isPresent()) {
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
           LOG.info(googleUser.toString());
            this.googleUserRepository.save(googleUser);
        } else {
            LOG.info("Bienvenido {}", user.getAttributes().get("given_name"));
        }
	}

}