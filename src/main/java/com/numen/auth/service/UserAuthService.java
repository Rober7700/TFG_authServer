package com.numen.auth.service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.numen.auth.dto.CreateUsuarioDto;
import com.numen.auth.dto.MensajeDto;
import com.numen.auth.entity.RecuperarPasswordToken;
import com.numen.auth.entity.Role;
import com.numen.auth.entity.Usuario;
import com.numen.auth.enumeration.RoleName;
import com.numen.auth.repository.IRoleRepository;
import com.numen.auth.repository.ITokenRepository;
import com.numen.auth.repository.IUsuarioRepository;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserAuthService {

	
	private final IUsuarioRepository usuarioRepository;
	private final ITokenRepository tokenRepository;
	private final IRoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	JavaMailSender javaMailSender;
	
	public MensajeDto crearUsuario(CreateUsuarioDto dto) {
		Usuario usuario = Usuario.builder()
				.username(dto.username())
				.password(passwordEncoder.encode(dto.password()))
				.build();
		Set<Role> roles = new HashSet<>();
		dto.roles().forEach(r -> {
			Role role =  roleRepository.findByRole(RoleName.valueOf(r))
					.orElseThrow(() -> new RuntimeException("rol no encontrado"));
			roles.add(role);
		});
		usuario.setRoles(roles);
		usuarioRepository.save(usuario);
		return new MensajeDto("Usuario " + usuario.getUsername() + " guardado");
	}

	public String enviarEmail(Usuario usuario) {
		try {
			String resetLink = generarResetToken(usuario);
			
			MimeMessage message = javaMailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true);
			helper.setFrom("admin@1");
			helper.setTo(usuario.getUsername());
			
			helper.setSubject("Recuperar Contraseña");
			StringBuilder sb = new StringBuilder();
			sb.append("Hola\n\n ");
			sb.append("Haz click en el siguiente enlace para recuperar tu contraseña: \n\n");
			sb.append("<a href=\"" + resetLink + "\">Restablecer contraseña</a>");
			sb.append("\n\n");
			sb.append("Gracias\n");
			sb.append("Numen.");
			helper.setText(sb.toString(), true);
			javaMailSender.send(message);

			return "success";
		} catch (Exception e) {
			e.printStackTrace();
			return "error";
		}
	}

	private String generarResetToken(Usuario usuario) {
		RecuperarPasswordToken token = tokenRepository.findByUsuarioId(usuario.getId());
    	if (token != null) {
    		tokenRepository.deleteById(token.getId());
    	}
		UUID uuid = UUID.randomUUID();
		LocalDateTime actual = LocalDateTime.now();
		LocalDateTime caduca = actual.plusMinutes(30);
		RecuperarPasswordToken resetToken = RecuperarPasswordToken.builder()
				.usuario(usuario)
				.token(uuid.toString())
				.caducidadToken(caduca)
				.build();
		RecuperarPasswordToken tokenGuardado = tokenRepository.save(resetToken);
		if (tokenGuardado != null) {
			String endpoint= "http://localhost:9000/resetPass";
			return endpoint + "/" + resetToken.getToken();
		}
		return "";
	}

	public boolean tokenCaducado(LocalDateTime caducidadToken) {
		LocalDateTime ahora = LocalDateTime.now();
		return caducidadToken.isAfter(ahora);
	}
	
}
