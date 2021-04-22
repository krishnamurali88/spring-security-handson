package com.example.demo.auth;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class ApplicationUser implements UserDetails {

	private final String username;
	private final String password;
	private final Set<? extends GrantedAuthority> grantedAuthorities;
	private final boolean isAccountNonExpired;
	private final boolean isAccountNonLocked;
	private final boolean isCredentialsNonExpired;
	private final boolean isEnabled;

	public ApplicationUser(String username, String password, Set<? extends GrantedAuthority> grantedAuthorities,
			boolean isAccountNonExpired, boolean isAccountNonLocked, boolean isCredentialsNonExpired,
			boolean isEnabled) {
		this.username = username;
		this.password = password;
		this.grantedAuthorities = grantedAuthorities;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isAccountNonLocked = isAccountNonLocked;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
		this.isEnabled = isEnabled;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public boolean isAccountNonExpired() {
		return isAccountNonExpired;
	}

	public boolean isAccountNonLocked() {
		return isAccountNonLocked;
	}

	public boolean isCredentialsNonExpired() {
		return isCredentialsNonExpired;
	}

	public boolean isEnabled() {
		return isEnabled;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return grantedAuthorities;
	}

	

}
