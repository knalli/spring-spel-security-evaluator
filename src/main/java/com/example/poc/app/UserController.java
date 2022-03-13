package com.example.poc.app;

import com.example.poc.app.security.AppPermissionExpressionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
// @el (hasUserReadPermissionOrIsHasRole: com.example.poc.app.security.AppMethodSecurityExpressionRoot)
public class UserController {

	private final AppPermissionExpressionEvaluator evaluator;

	@GetMapping("/{id}")
	@PreAuthorize("hasPermission(#id, 'USER', 'READ')")
	public String get(@AuthenticationPrincipal UserDetails user,
	                  @PathVariable int id) {
		return "Yeah, it works";
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasPermission(#id, 'USER', 'DELETE') || hasRole('ADMIN')")
	public String delete(@AuthenticationPrincipal UserDetails user,
	                     @PathVariable int id) {
		return "Yeah, it works";
	}

	@GetMapping("/{id}/hidden")
	@PreAuthorize("hasUserReadPermissionOrIsHasRole(#id, 'FAKER')")
	public String hiddenOperation(@AuthenticationPrincipal UserDetails user,
	                              @PathVariable int id) {
		return "Yeah, it works";
	}

	@GetMapping("/hasRead")
	public String hasRead() {
		var result = evaluator.evaluateExpression("isAuthenticated()");
		return "result: " + result;
	}

	@GetMapping("/hasDelete")
	public String hasDelete() {
		var result = evaluator.evaluateExpression("hasPermission(#id, 'USER', 'DELETE') || hasRole('ADMIN')",
		                                          Map.of("id", 1));
		return "result: " + result;
	}

	@GetMapping("/hasRead2")
	public String hasRead2() throws NoSuchMethodException {
		final var type = UserController.class;
		var result = evaluator.evaluateMethodPreAuthorize(type, type.getMethod("get", UserDetails.class, int.class),
		                                                  Map.of("id", 1));
		return "result: " + result;
	}

	@GetMapping("/hasDelete2")
	public String hasDelete2() throws NoSuchMethodException {
		final var type = UserController.class;
		var result = evaluator.evaluateMethodPreAuthorize(type, type.getMethod("delete", UserDetails.class, int.class),
		                                                  Map.of("id", 1));
		return "result: " + result;
	}

}
