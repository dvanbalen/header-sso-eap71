package com.redhat.consulting.sso.undertow;

import static com.redhat.consulting.sso.undertow.HttpHeaderMechanismFactory.MECHANISM_NAME;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.jboss.logging.Logger;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;

import com.redhat.consulting.sso.elytron.HttpHeaderEvidence;

public class HttpHeaderAuthenticationMechanism implements HttpServerAuthenticationMechanism {

	private static final Logger LOG = Logger.getLogger(HttpHeaderAuthenticationMechanism.class);

	private static final String USERNAME_HEADER = "X-USERNAME";
	private static final String ROLES_HEADER = "X-ROLES";
	private static final String MESSAGE_HEADER = "X-MESSAGE";

	private static final HttpServerMechanismsResponder RESPONDER = new HttpServerMechanismsResponder() {
		public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
			response.addResponseHeader(MESSAGE_HEADER,
					"Please resubit the request with a username specified using the required HTTP headers.");
			response.setStatusCode(401);
		}
	};

	private final CallbackHandler callbackHandler;

	HttpHeaderAuthenticationMechanism(final CallbackHandler callbackHandler) {
		this.callbackHandler = callbackHandler;
	}

	public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
		final String username = request.getFirstRequestHeaderValue(USERNAME_HEADER);
		final String roles = request.getFirstRequestHeaderValue(ROLES_HEADER);

		LOG.debug("USER: " + username + " ROLES: " + roles);

		// This login method requires a username and zero or more roles
		if (username == null || username.length() == 0 || roles == null) {

			// This mechanism is not performing authentication at this time however other
			// mechanisms may be in use concurrently and could succeed so we register

			request.noAuthenticationInProgress(RESPONDER);
			return;
		}

		// Assume username and roles were verified by caller and authenticate

		try {
			//Store headers for later use by application
			HttpHeaderEvidence headerEvidence = new HttpHeaderEvidence(username, roles);
			EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(headerEvidence);

			callbackHandler.handle(new Callback[] { evidenceVerifyCallback });

			if (evidenceVerifyCallback.isVerified() == false) {
				request.authenticationFailed("Username / Password Validation Failed", RESPONDER);
			}

			AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);

			callbackHandler.handle(new Callback[] { authorizeCallback });

			// Callback to report outcome of auth process
			if (authorizeCallback.isAuthorized()) {
				callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
				request.authenticationComplete();
			} else {
				callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
				request.authenticationFailed("Authorization check failed.", RESPONDER);
			}
			return;
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}

	}

	public String getMechanismName() {
		return MECHANISM_NAME;
	}

}
