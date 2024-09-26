package com.example.springbootbasic.config;

import com.example.springbootbasic.entiry.Account;
import com.example.springbootbasic.entiry.Authority;
import com.example.springbootbasic.entiry.Post;
import com.example.springbootbasic.service.AccountService;
import com.example.springbootbasic.service.AuthorityService;
import com.example.springbootbasic.service.PostService;
import com.example.springbootbasic.util.Privileges;
import com.example.springbootbasic.util.Roles;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class SeedData implements CommandLineRunner {

    private final PostService postService;

    private final AccountService accountService;

    private final AuthorityService authorityService;

    // 자동실행 -> 초기화하기 위해
    @Override
    public void run(String... args) throws Exception {

         for(Privileges auth : Privileges.values()){
             Authority authority=new Authority();
             authority.setId(auth.getId());
             authority.setName(auth.getPrivilege());
             authorityService.save(authority);
         }

        Account account01 = new Account();
        Account account02 = new Account();
        Account account03 = new Account();
        Account account04 = new Account();

        account01.setEmail("user@user.com");
        account01.setPassword("pass987");
        account01.setFirstname("User");
        account01.setLastname("lastname");

        account02.setEmail("admin@admin.com");
        account02.setPassword("pass987");
        account02.setFirstname("Admin");
        account02.setLastname("lastname");
        account02.setRole(Roles.ADMIN.getRole()); // "ROLE_ADMIN"

        account03.setEmail("editor@editor.com");
        account03.setPassword("pass987");
        account03.setFirstname("Editor");
        account03.setLastname("lastname");
        account03.setRole(Roles.EDITOR.getRole());

        account04.setEmail("super_editor@editor.com");
        account04.setPassword("pass987");
        account04.setFirstname("Editor");
        account04.setLastname("lastname");
        account04.setRole(Roles.EDITOR.getRole());
        Set<Authority> authorities = new HashSet<>();
        authorityService.findById(Privileges.ACCESS_ADMIN_PANEL.getId()).ifPresent(authorities::add);
        authorityService.findById(Privileges.RESET_ANY_USER_PASSWORD.getId()).ifPresent(authorities::add);
        account04.setAuthorities(authorities);

        accountService.save(account01);
        accountService.save(account02);
        accountService.save(account03);
        accountService.save(account04);

        // 데이터 초기화....
               List<Post> posts=postService.getAll();
               if(posts.size()==0){
                   Post post01=new Post();
                   post01.setTitle("Post 01");
                   post01.setBody("Post 01 body........................");
                   post01.setAccount(account01);
                   postService.save(post01);

                   Post post02=new Post();
                   post02.setTitle("Post 02");
                   post02.setBody("Post 02 body........................");
                   post02.setAccount(account02);
                   postService.save(post02);
               }
    }
}
