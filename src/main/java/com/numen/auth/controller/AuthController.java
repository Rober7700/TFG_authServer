package com.numen.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.numen.auth.dto.CreateUsuarioDto;
import com.numen.auth.dto.MensajeDto;
import com.numen.auth.service.UserAuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

	private final UserAuthService userAuthService;
	
	@PostMapping("/create")
	public ResponseEntity<MensajeDto> crearUser(@RequestBody CreateUsuarioDto dto){
		System.out.println(dto);
		return ResponseEntity.status(HttpStatus.CREATED).body(userAuthService.crearUsuario(dto));
	}

}
