package com.example.springbootbasic.controller;

import com.example.springbootbasic.entiry.Account;
import com.example.springbootbasic.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accountService;

    @GetMapping("/register")
    public String register(Model model){
        Account account=new Account();
        model.addAttribute("account", account);
        return "register";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute Account account){
              accountService.save(account);
              return "redirect:/";
    }

    @GetMapping("/login")
    public String login(Model model){
         return "login";
     }

    @GetMapping("/profile")
    public String profile(Model model){
        return "profile";
    }

    @GetMapping("/test")
    public String test(Model model){
        return "test";
    }
}
