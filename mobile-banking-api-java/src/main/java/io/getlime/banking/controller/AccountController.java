package io.getlime.banking.controller;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.banking.security.model.ApiAuthentication;

@Controller
@RequestMapping(value = "/secured/accounts")
public class AccountController {
	
	private class Account {
		
	}
	
	private String getUserId() throws Exception {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication.getClass().equals(ApiAuthentication.class)) {
			return ((ApiAuthentication)authentication).getUserId();
		} else {
			throw new Exception("INVALID_AUTHENTICATION_OBJECT");
		}
	}
	
	@RequestMapping
	public @ResponseBody List<Account> accountList() throws Exception {
		String userId = getUserId();
		// fetch accounts from back-end systems for a given user
		return null;
	}

}
