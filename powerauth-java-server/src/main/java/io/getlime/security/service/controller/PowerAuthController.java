package io.getlime.security.service.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import io.getlime.security.powerauth.BlockActivationRequest;
import io.getlime.security.powerauth.BlockActivationResponse;
import io.getlime.security.powerauth.CommitActivationRequest;
import io.getlime.security.powerauth.CommitActivationResponse;
import io.getlime.security.powerauth.GetActivationListForUserRequest;
import io.getlime.security.powerauth.GetActivationListForUserResponse;
import io.getlime.security.powerauth.GetActivationStatusRequest;
import io.getlime.security.powerauth.GetActivationStatusResponse;
import io.getlime.security.powerauth.InitActivationRequest;
import io.getlime.security.powerauth.InitActivationResponse;
import io.getlime.security.powerauth.PrepareActivationRequest;
import io.getlime.security.powerauth.PrepareActivationResponse;
import io.getlime.security.powerauth.RemoveActivationRequest;
import io.getlime.security.powerauth.RemoveActivationResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VerifySignatureRequest;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.service.PowerAuthService;

@Controller
@RequestMapping(value = "/pa")
public class PowerAuthController {

    @Autowired
    private PowerAuthService powerAuthService;

    @RequestMapping(value = "activation/init", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<InitActivationResponse> initActivation(@RequestBody RESTRequestWrapper<InitActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.initActivation(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/prepare", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<PrepareActivationResponse> prepareActivation(@RequestBody RESTRequestWrapper<PrepareActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.prepareActivation(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/commit", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<CommitActivationResponse> commitActivation(@RequestBody RESTRequestWrapper<CommitActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.commitActivation(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/status", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<GetActivationStatusResponse> getActivationStatus(@RequestBody RESTRequestWrapper<GetActivationStatusRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getActivationStatus(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/remove", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<RemoveActivationResponse> removeActivation(@RequestBody RESTRequestWrapper<RemoveActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.removeActivation(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/list", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<GetActivationListForUserResponse> getActivatioListForUser(@RequestBody RESTRequestWrapper<GetActivationListForUserRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.getActivatioListForUser(request.getRequestObject()));
    }

    @RequestMapping(value = "signature/verify", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<VerifySignatureResponse> verifySignature(@RequestBody RESTRequestWrapper<VerifySignatureRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.verifySignature(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/block", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<BlockActivationResponse> blockActivation(@RequestBody RESTRequestWrapper<BlockActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.blockActivation(request.getRequestObject()));
    }

    @RequestMapping(value = "activation/unblock", method = RequestMethod.POST)
    public @ResponseBody RESTResponseWrapper<UnblockActivationResponse> unblockActivation(@RequestBody RESTRequestWrapper<UnblockActivationRequest> request) throws Exception {
        return new RESTResponseWrapper<>("OK", powerAuthService.unblockActivation(request.getRequestObject()));
    }

}
