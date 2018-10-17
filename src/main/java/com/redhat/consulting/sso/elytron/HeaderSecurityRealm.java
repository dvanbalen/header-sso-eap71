package com.redhat.consulting.sso.elytron;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.jboss.logging.Logger;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

public class HeaderSecurityRealm implements SecurityRealm {

	private static final Logger LOG = Logger.getLogger(HeaderSecurityRealm.class);

	private final String ROLE_SEPARATOR = "[\\\\s]*,[\\\\s]*";
	private final String ROLES_LOCATION = RoleDecoder.KEY_ROLES;
	
	@Override
	public RealmIdentity getRealmIdentity(final Evidence evidence) {
		return new HeaderRealmIdentity(evidence);
	}

	public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> arg0, String algorithmName,
			AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
		return SupportLevel.UNSUPPORTED;
	}

	public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String arg1)
			throws RealmUnavailableException {
		if(evidenceType != null && isHttpHeaderEvidence(evidenceType.getClass())) {
			return SupportLevel.POSSIBLY_SUPPORTED;
		}
		
		return SupportLevel.UNSUPPORTED;
	}
	
	private boolean isHttpHeaderEvidence(Class<?> evidenceType) {
		return HttpHeaderEvidence.class.equals(evidenceType);
	}

	private final class HeaderRealmIdentity implements RealmIdentity {

		private final HttpHeaderEvidence evidence;
		private Attributes claims;

		HeaderRealmIdentity(Evidence evidence) {
			if (evidence != null && isHttpHeaderEvidence(evidence.getClass())) {
				this.evidence = HttpHeaderEvidence.class.cast(evidence);
			} else {
				this.evidence = null;
			}
		}

		public boolean exists() throws RealmUnavailableException {
			return getClaims() != null;
		}

		public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
			return null;
		}

		public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
				AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
			return SupportLevel.UNSUPPORTED;
		}

		public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
				throws RealmUnavailableException {
			if(exists() && isHttpHeaderEvidence(evidenceType)) {
				return SupportLevel.SUPPORTED;
			}
			
			return SupportLevel.UNSUPPORTED;
		}

		public Principal getRealmIdentityPrincipal() {
			return new NamePrincipal(evidence.getUsername());
		}

		public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
			if (isHttpHeaderEvidence(evidence.getClass())) {
				HttpHeaderEvidence headerEvidence = HttpHeaderEvidence.class.cast(evidence);
				LOG.debug("Returning roles: "+headerEvidence.getRoles());
				return headerEvidence != null && headerEvidence.getUsername() != null && headerEvidence.getUsername().length() > 0
						&& headerEvidence.getRoles() != null;
			}
			return false;
		}
		
		@Override
		public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
			if(exists()) {
				return new AuthorizationIdentity() {
					@Override
					public Attributes getAttributes() {
						return claims;
					}
				};
			}
			
			return null;
		}
		
		private Attributes getClaims() {
			if(this.claims==null) {
				this.claims = parseRoles(this.evidence);
			}
			
			return this.claims;
		}
		
		private Attributes parseRoles(Evidence evidence) {
			if(!isHttpHeaderEvidence(evidence.getClass())) {
				return null;
			}
			HttpHeaderEvidence headerEvidence = HttpHeaderEvidence.class.cast(evidence);
			String rolesString = headerEvidence.getRoles();
			LOG.debug("Roles string to parse: "+rolesString);
			Attributes map = new MapAttributes();
			Set<String> roles = new HashSet<String>(Arrays.asList(rolesString.split(ROLE_SEPARATOR)));
			map.addAll(ROLES_LOCATION, roles);
			
			return map;
			
		}

	}
}
