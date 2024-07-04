package com.numen.auth.dto;

import java.util.List;

public record CreateUsuarioDto (String username, String password, List<String> roles) {}
