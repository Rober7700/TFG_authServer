package com.numen.auth.entity;

import org.springframework.security.oauth2.core.user.OAuth2User;

import jakarta.persistence.Entity;
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
@Table(name = "auth_googleClientes")
public class GoogleUser {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	private String email;
	private String pictureUrl;
	

    public static GoogleUser fromOauth2User(OAuth2User user){
        GoogleUser googleUser = GoogleUser.builder()
                .email(user.getName())
                .pictureUrl(user.getAttributes().get("picture").toString())
                .build();
        return googleUser;
    }

    @Override
    public String toString() {
        return "GoogleUser{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", pictureUrl='" + pictureUrl + '\'' +
                '}';
    }
}
