package com.numen.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.numen.auth.entity.RecuperarPasswordToken;

@Repository
public interface ITokenRepository extends JpaRepository<RecuperarPasswordToken, Long>{

	Optional<RecuperarPasswordToken> findByToken(String token);

	RecuperarPasswordToken findByUsuarioId(int id);

}
