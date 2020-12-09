package com.iuvya.springsecuritystudy.controller;

import org.springframework.web.bind.annotation.*;

/**
 * @author ziyou
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @RequestMapping(value = "/index", method = {RequestMethod.GET, RequestMethod.POST})
    public String index() {
        return "index";
    }

    @RequestMapping(value = "/errorMsg", method = {RequestMethod.GET, RequestMethod.POST})
    //@GetMapping("errorMsg")
    public String error() {
        return "error";
    }

}
