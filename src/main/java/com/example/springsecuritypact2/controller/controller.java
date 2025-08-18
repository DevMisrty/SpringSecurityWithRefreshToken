package com.example.springsecuritypact2.controller;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class controller {

    @GetMapping("/home")
    public String getHome(){
        return "This is home page for public access";
    }

    @GetMapping("/page1")
    public String getPage1(){
        return "This is Page 1" ;
    }

    @GetMapping("/adminPage")
    public String getAdminPage(){
        return "This is Admin Page";
    }
}
