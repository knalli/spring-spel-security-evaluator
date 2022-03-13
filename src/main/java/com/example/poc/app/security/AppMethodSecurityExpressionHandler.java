package com.example.poc.app.security;

import org.aopalliance.intercept.Joinpoint;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import java.util.Optional;

public class AppMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(final Authentication authentication,
	                                                                          final MethodInvocation invocation) {
		final var root = new AppMethodSecurityExpressionRoot(authentication);
		Optional.of(invocation)
		        .map(Joinpoint::getThis)
		        .ifPresent(root::setThis);
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());
		return root;
	}

}
