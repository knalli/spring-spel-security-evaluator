package com.example.poc.app.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends GlobalMethodSecurityConfiguration {

	// Make method-security-expression-handler available as bean
	@Configuration
	@RequiredArgsConstructor
	public static class SecurityExpressionHandlerConfig implements SmartInitializingSingleton {

		private final ApplicationContext context;

		private AppMethodSecurityExpressionHandler instance;

		@Bean
		public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
			final var expressionHandler = new AppMethodSecurityExpressionHandler();
			this.instance = expressionHandler;
			return expressionHandler;
		}

		@Nullable
		private <T> T getSingleBeanOrNull(Class<T> type) {
			try {
				return this.context.getBean(type);
			} catch (NoSuchBeanDefinitionException ex) {
			}
			return null;
		}

		@Override
		public void afterSingletonsInstantiated() {
			// see GlobalMethodSecurityConfiguration#afterSingletonsInstantiated
			final var permissionEvaluator = getSingleBeanOrNull(PermissionEvaluator.class);
			if (permissionEvaluator != null) {
				this.instance.setPermissionEvaluator(permissionEvaluator);
			}
			final var roleHierarchy = getSingleBeanOrNull(RoleHierarchy.class);
			if (roleHierarchy != null) {
				this.instance.setRoleHierarchy(roleHierarchy);
			}
			final var trustResolver = getSingleBeanOrNull(AuthenticationTrustResolver.class);
			if (trustResolver != null) {
				this.instance.setTrustResolver(trustResolver);
			}
			final var grantedAuthorityDefaults = getSingleBeanOrNull(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaults != null) {
				this.instance.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
		}
	}

	private final MethodSecurityExpressionHandler methodSecurityExpressionHandler;

	@Override
	protected MethodSecurityExpressionHandler createExpressionHandler() {
		return methodSecurityExpressionHandler;
	}

	// required only if supporting "hasPermission()"
	@Bean
	public PermissionEvaluator permissionEvaluator() {
		return new CustomPermissionEvaluator();
	}

	@Bean
	public AppPermissionExpressionEvaluator appPermissionExpressionEvaluator() {
		return new AppPermissionExpressionEvaluator(createExpressionHandler());
	}

}
