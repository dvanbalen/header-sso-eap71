package com.redhat.consulting.sso.elytron;

import org.wildfly.security.evidence.Evidence;

public class HttpHeaderEvidence implements Evidence {

	private String username;
	private String roles;

	public HttpHeaderEvidence(String userName, String userRoles) {
		if (userName != null && userName.length() != 0)
			this.username = userName;
		if (userRoles != null & userRoles.length() != 0)
			this.roles = userRoles;
	}

	public String getUsername() {
		return username;
	}

	public String getRoles() {
		return roles;
	}

}
