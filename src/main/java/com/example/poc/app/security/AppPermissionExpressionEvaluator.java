package com.example.poc.app.security;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.SimpleMethodInvocation;

import java.lang.reflect.Method;
import java.util.Map;

public class AppPermissionExpressionEvaluator {

	private final MethodSecurityExpressionHandler methodSecurityExpressionHandler;

	private final Class<PseudoObject> pseudoType;
	private final Method pseudoMethod;

	/**
	 * This pseudo object is required as a fake/pseudo target within the method security expression handler.
	 */
	private static final class PseudoObject {
		public void pseudo() {
		}
	}

	public AppPermissionExpressionEvaluator(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.methodSecurityExpressionHandler = methodSecurityExpressionHandler;
		this.pseudoType = PseudoObject.class;
		try {
			this.pseudoMethod = PseudoObject.class.getDeclaredMethod("pseudo");
		} catch (final NoSuchMethodException e) {
			throw new IllegalStateException("Invalid reflection", e);
		}
	}

	public boolean evaluateMethodPreAuthorize(final Class<?> type,
	                                          final Method method) {
		return evaluateMethodPreAuthorize(type, method, Map.of());
	}

	public boolean evaluateMethodPreAuthorize(final Class<?> type,
	                                          final Method method,
	                                          final Map<String, Object> variables) {
		final var parser = new SpelExpressionParser();
		final var authentication = SecurityContextHolder.getContext().getAuthentication();
		final var context = methodSecurityExpressionHandler.createEvaluationContext(authentication,
		                                                                            new SimpleMethodInvocation(type, method));
		final var expression = method.getDeclaredAnnotation(PreAuthorize.class).value();
		variables.forEach(context::setVariable);
		return ExpressionUtils.evaluateAsBoolean(parser.parseExpression(expression), context);
	}

	public boolean evaluateExpression(final String expression) {
		return evaluateExpression(expression, Map.of());
	}

	public boolean evaluateExpression(final String expression, final Map<String, Object> variables) {
		final var parser = new SpelExpressionParser();
		final var authentication = SecurityContextHolder.getContext().getAuthentication();
		final var context = methodSecurityExpressionHandler.createEvaluationContext(authentication,
		                                                                            new SimpleMethodInvocation(pseudoType, pseudoMethod));
		variables.forEach(context::setVariable);
		return ExpressionUtils.evaluateAsBoolean(parser.parseExpression(expression), context);
	}

}
