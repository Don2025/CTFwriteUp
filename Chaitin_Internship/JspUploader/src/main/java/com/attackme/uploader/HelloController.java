package com.attackme.uploader;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HelloController {
    @RequestMapping("/success")
    public String hello(Model model, @RequestParam(value="name", required=false, defaultValue="bro") String name) {
        model.addAttribute("name", name);
        return "success";
    }
}
