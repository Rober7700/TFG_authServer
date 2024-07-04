package com.numen.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.numen.auth.dto.CreateClienteDto;
import com.numen.auth.dto.MensajeDto;
import com.numen.auth.service.ClienteService;

@RestController
@RequestMapping("/cliente")
public class ClienteController {

	@Autowired
	private ClienteService clienteService;

	@PostMapping("/create")
	public ResponseEntity<MensajeDto> create(@RequestBody CreateClienteDto dto) {
		return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.create(dto));
	}

}