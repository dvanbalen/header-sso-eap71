package com.redhat.consulting.sso.undertow;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.jboss.logging.Logger;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

public class HttpHeaderMechanismFactory implements HttpServerAuthenticationMechanismFactory {

	private static final Logger LOG = Logger.getLogger(HttpHeaderMechanismFactory.class);

    static final String MECHANISM_NAME = "HTTP_HEADER_MECHANISM";

    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String name, Map<String, ?> properties, CallbackHandler handler) throws HttpAuthenticationException {
        if (MECHANISM_NAME.equals(name)) {
        	LOG.debug("Creating new instance of "+HttpHeaderAuthenticationMechanism.class.getName());
            return new HttpHeaderAuthenticationMechanism(handler);
        }

        return null;
    }

    public String[] getMechanismNames(Map<String, ?> properties) {
        return new String[] { MECHANISM_NAME };
    }

}
