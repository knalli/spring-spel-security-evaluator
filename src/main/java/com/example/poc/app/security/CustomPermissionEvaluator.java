package com.example.poc.app.security;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

@Log4j2
public class CustomPermissionEvaluator implements PermissionEvaluator {

	@Override
	public boolean hasPermission(final Authentication authentication,
	                             final Object targetDomainObject,
	                             final Object permission) {
		log.info("hasPermission {} - {}", authentication, permission);
		return true;
	}

	@Override
	public boolean hasPermission(final Authentication authentication,
	                             final Serializable targetId,
	                             final String targetType,
	                             final Object permission) {
		log.info("hasPermission {}:{} {} - {}", targetType, targetId, authentication, permission);
		return true;
	}

}
