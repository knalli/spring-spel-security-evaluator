package com.example.poc.app.security;

import lombok.extern.log4j.Log4j2;
import org.springframework.lang.Nullable;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

@Log4j2
public class AppMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private Object filterObject;
	private Object returnObject;
	private Object target;

	/**
	 * @see SecurityExpressionRoot
	 */
	public AppMethodSecurityExpressionRoot(final Authentication authentication) {
		super(authentication);
	}

	@Override
	public void setFilterObject(final Object filterObject) {
		this.filterObject = filterObject;
	}

	@Override
	@Nullable
	public Object getFilterObject() {
		return filterObject;
	}

	@Override
	public void setReturnObject(final Object returnObject) {
		this.returnObject = returnObject;
	}

	@Override
	@Nullable
	public Object getReturnObject() {
		return returnObject;
	}

	@Override
	@Nullable
	public Object getThis() {
		return target;
	}

	// required, see also MethodSecurityExpressionRoot
	@SuppressWarnings("unused")
	void setThis(Object target) {
		this.target = target;
	}

	// below all additional functions available in authorizing checks like @PreAuthorize

	@SuppressWarnings("unused")
	public boolean hasUserReadPermissionOrIsHasRole(final Serializable targetId, final Serializable role) {
		log.info("hasUserReadPermissionOrIsHasRole called {} / {} - {}", targetId, role, authentication);
		return hasPermission(targetId, "USER", "READ") || hasRole(role.toString());
	}

}
