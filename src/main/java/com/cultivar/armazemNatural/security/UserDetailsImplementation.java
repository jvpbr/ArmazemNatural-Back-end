package com.cultivar.armazemNatural.security;

import java.util.Collection;
import java.util.List;

import com.cultivar.armazemNatural.model.Usuario;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserDetailsImplementation implements UserDetails {
	
private static final long serialVersionUID = 1L;
	
	private String userEmail;
	private String password;
	private List<GrantedAuthority> authorities;
	
	public UserDetailsImplementation(Usuario user) {
		this.userEmail = user.getEmail();
		this.password = user.getSenha();
	}
	
	public UserDetailsImplementation() {}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userEmail;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
