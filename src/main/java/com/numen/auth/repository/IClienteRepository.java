package com.numen.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.numen.auth.entity.Cliente;

@Repository
public interface IClienteRepository extends JpaRepository<Cliente, Long> {

	Optional<Cliente> findByClienteId(String clienteId);
}
