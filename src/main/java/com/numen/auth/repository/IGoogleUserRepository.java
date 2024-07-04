package com.numen.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.numen.auth.entity.GoogleUser;

@Repository
public interface IGoogleUserRepository extends JpaRepository<GoogleUser, Long> {
	Optional<GoogleUser> findByEmail(String email);
}
