package com.numen.auth.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.numen.auth.dto.CreateUsuarioDto;
import com.numen.auth.entity.RecuperarPasswordToken;
import com.numen.auth.entity.Usuario;
import com.numen.auth.repository.ITokenRepository;
import com.numen.auth.repository.IUsuarioRepository;
import com.numen.auth.service.UserAuthService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class LoginController {

	private final UserAuthService userAuthService;
	@Autowired
	private final IUsuarioRepository usuarioRepository;
	private final ITokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/register")
	public String register() {
		return "register";
	}

	@PostMapping("/register")
	public String crearUser(@RequestParam(required = true, name = "username") String username,
			@RequestParam(required = true, name = "password") String password, Model model,
			RedirectAttributes redirectAttributes) {
		List<String> roles = new ArrayList<>();
		roles.add("ROLE_USER");

		Optional<Usuario> existeUser = usuarioRepository.findByUsername(username);
		if (existeUser.isPresent()) {
			model.addAttribute("error", "El usuario ya existe");
			return "register";
		}

		CreateUsuarioDto newUser = new CreateUsuarioDto(username, password, roles);
		userAuthService.crearUsuario(newUser);
		redirectAttributes.addFlashAttribute("success", "¡Usuario registrado exitosamente! Por favor, inicia sesión.");
		return "redirect:/login";
	}

	@GetMapping("/recover")
	public String recover() {
		return "recover";
	}

	@PostMapping("/recover")
	public String recoverPassword(@RequestParam(required = true, name = "username") String username, Model model,
			RedirectAttributes redirectAttributes) {
		Optional<Usuario> optionalUser = usuarioRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			Usuario user = optionalUser.get();
			String output = userAuthService.enviarEmail(user);
			if (output.equals("success")) {
				redirectAttributes.addFlashAttribute("success",
						"¡Usuario registrado exitosamente! Por favor, inicia sesión.");
				return "redirect:/register";
			}
		}
		redirectAttributes.addFlashAttribute("error", "El usuario no tiene cuenta registrada.");
		return "redirect:/register";
	}
	
    @GetMapping("/resetPass/{token}")
    public String resetPass(@PathVariable String token, Model model, RedirectAttributes redirectAttributes) {
    	Optional<RecuperarPasswordToken> optionalToken = tokenRepository.findByToken(token);
    	if (optionalToken.isPresent() && userAuthService.tokenCaducado(optionalToken.get().getCaducidadToken())) {
    		RecuperarPasswordToken tokenPass = optionalToken.get();
    		model.addAttribute("email", tokenPass.getUsuario().getUsername());
    		tokenRepository.delete(tokenPass);
    		return "resetPass";
    	}
		redirectAttributes.addFlashAttribute("error", "El usuario no tiene cuenta registrada.");
		return "redirect:/login";
    }

    @PostMapping("/resetPass")
    public String resetPassProceso(@RequestParam(required = true, name = "username") String username,
			@RequestParam(required = true, name = "password") String password, Model model,
			RedirectAttributes redirectAttributes) {
    	Optional<Usuario> optionalUser = usuarioRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			optionalUser.get().setPassword(passwordEncoder.encode(password));
			usuarioRepository.save(optionalUser.get());
			redirectAttributes.addFlashAttribute("success", "Has cambiado la contraseña.");
		}
		return "redirect:/login";
    }
    
    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }

	@PostMapping("/logout")
	public String logoutOK(HttpSecurity http) throws Exception {
		http.logout(logout -> logout.deleteCookies("JSESSIONID").invalidateHttpSession(true).clearAuthentication(true));
		return "login?logout";
	}

}