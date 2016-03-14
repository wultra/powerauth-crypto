package io.getlime.security.admin.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import io.getlime.powerauth.soap.CreateApplicationResponse;
import io.getlime.powerauth.soap.GetApplicationDetailResponse;
import io.getlime.powerauth.soap.GetApplicationListResponse;
import io.getlime.security.soap.client.PowerAuthServiceClient;

@Controller
public class ApplicationController {

	@Autowired
	private PowerAuthServiceClient client;

	@RequestMapping(value = "/")
	public String homePage() {
		return "redirect:/application/list";
	}

	@RequestMapping(value = "/application/list")
	public String applicationList(Map<String, Object> model) {
		List<GetApplicationListResponse.Applications> applicationList = client.getApplicationList();
		model.put("applications", applicationList);
		return "applications";
	}

	@RequestMapping(value = "/application/create")
	public String applicationCreate(Map<String, Object> model) {
		return "applicationCreate";
	}

	@RequestMapping(value = "/application/detail/{id}/version/create")
	public String applicationVersionCreate(@PathVariable Long id, Map<String, Object> model) {
		model.put("applicationId", id);
		return "applicationVersionCreate";
	}

	@RequestMapping(value = "/application/create/do.submit", method = RequestMethod.POST)
	public String applicationCreateAction(@RequestParam String name) {
		CreateApplicationResponse application = client.createApplication(name);
		return "redirect:/application/detail/" + application.getApplicationId();
	}

	@RequestMapping(value = "/application/detail/{applicationId}/version/create/do.submit", method = RequestMethod.POST)
	public String applicationVersionCreateAction(@PathVariable Long applicationId, @RequestParam String name) {
		client.createApplicationVersion(applicationId, name);
		return "redirect:/application/detail/" + applicationId;
	}

	@RequestMapping(value = "/application/detail/{id}/version/update/do.submit", method = RequestMethod.POST)
	public String applicationUpdateAction(
			@RequestParam(value = "version", required = false) Long version,
			@RequestParam(value = "enabled") Boolean enabled,
			@PathVariable(value = "id") Long id) {
		if (enabled) {
			client.supportApplicationVersion(version);
		} else {
			client.unsupportApplicationVersion(version);
		}
		return "redirect:/application/detail/" + id;
	}

	@RequestMapping(value = "/application/detail/{id}")
	public String applicationDetail(@PathVariable(value = "id") Long id, Map<String, Object> model) {
		GetApplicationDetailResponse applicationDetails = client.getApplicationDetail(id);
		model.put("id", applicationDetails.getApplicationId());
		model.put("name", applicationDetails.getApplicationName());
		model.put("masterPublicKey", applicationDetails.getMasterPublicKey());
		model.put("versions", applicationDetails.getVersions());
		return "applicationDetail";
	}

}
