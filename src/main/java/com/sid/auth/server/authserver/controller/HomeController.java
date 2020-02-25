package com.sid.auth.server.authserver.controller;

import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

@Controller
public class HomeController {

    @GetMapping("/")
    public String getHome(){
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String getLogin(){
        return "login";
    }

    @GetMapping("/exit")
    public void exit(HttpServletRequest request, HttpServletResponse response){
        String requestURI = request.getRequestURI();
        String referer = request.getHeader("Referer");
        Enumeration<String> headerNames = request.getHeaderNames();
        new SecurityContextLogoutHandler().logout(request,null,null);
        try{

            response.sendRedirect(request.getHeader("Referer"));
        }catch (Exception e){
        e.printStackTrace();}
    }
}
