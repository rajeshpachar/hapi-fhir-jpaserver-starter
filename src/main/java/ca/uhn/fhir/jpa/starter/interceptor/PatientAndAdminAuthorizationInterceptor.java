package ca.uhn.fhir.jpa.starter.interceptor;

import java.util.List;

import org.apache.commons.codec.binary.Base64;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;

@Interceptor
public class PatientAndAdminAuthorizationInterceptor extends AuthorizationInterceptor {

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {

		boolean userIsUser = false;
		boolean userIsAdmin = false;
		String authHeader = theRequestDetails.getHeader("Authorization");
		String base64 = authHeader.substring("Basic ".length());
		String base64decoded = new String(Base64.decodeBase64(base64));
		String[] parts = base64decoded.split(":");

		String username = parts[0];
		String password = parts[1];

		if ("user".equals(username) && "password".equals(password)) {
			userIsUser = true;
		} else if ("admin".equals(username) && "admin".equals(password)) {
			userIsAdmin = true;
		} else {
			throw new AuthenticationException(Msg.code(644) + "Missing or invalid Authorization header value");
		}
		if (userIsUser) {
			return new RuleBuilder().allow().read().resourcesOfType("Patient").withAnyId().andThen().allow().write()
					.resourcesOfType("Patient").withAnyId().andThen().denyAll().build();
		}
		if (userIsAdmin) {
			return new RuleBuilder().allowAll().build();
		}
		return new RuleBuilder().denyAll().build();
	}
}
