package com.sid.auth.server.authserver.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RestController
@RequestMapping("user")
public class UserController {

    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;


    @Autowired
    private ConsumerTokenServices consumerTokenServices;

//    @Autowired
//    private TokenStore tokenStore;


    @GetMapping("/me")
    public Principal user(Principal principal) {


        return principal;
    }

    @GetMapping("/revoke/token/{tokenId}")
    public Boolean revokeToken(@PathVariable("tokenId") String token){

//        List<String> tokenValues = new ArrayList<String>();
//        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId("SampleClientId");
//        if (tokens!=null){
//            for (OAuth2AccessToken tok:tokens){
//                tokenValues.add(tok.getValue());
//            }
//        }
//
//        boolean b = consumerTokenServices.revokeToken(token);

        return true;
    }


}
