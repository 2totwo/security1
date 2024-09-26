package com.example.springbootbasic.service;

import com.example.springbootbasic.entiry.Account;
import com.example.springbootbasic.entiry.Authority;
import com.example.springbootbasic.repository.AccountRepository;
import com.example.springbootbasic.util.Roles;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AccountService  implements UserDetailsService {

     private final AccountRepository accountRepository;

     private final PasswordEncoder passwordEncoder; // 암호화 객체

     // 회원등록
     public Account save(Account account){
         // 비밀번호 암호화
         account.setPassword(passwordEncoder.encode(account.getPassword()));
         // 권한추가
         // ROLE_USER, ROLE_ADMIN, ROLE_EDITOR
         if(account.getRole()==null) { // 롤이 없으면
             // account.setRole(Roles.USER.getRole());
             account.setRole("ROLE_USER");
         }
         return accountRepository.save(account);
     }

     // 데이터베이스연동
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<Account> optionalAccount=accountRepository.findOneByEmailIgnoreCase(email); // IgnoreCase: 대소문자 구별x
        if(!optionalAccount.isPresent()){
              throw  new UsernameNotFoundException("Account not found");
        }
        // '1','user@user.com','User','lastname','$2a$10$dI1HPsrdaTy6FT4GAkQeAOaiLhgei0yg4omTHqpcNsfZHY4bqT/yO','ROLE_USER'
        // 역할 : "ROLE_USER" -> String을 GrantedAuthority("ROLE_USER")로 넣어주어야 함

        // '4','super_editor@editor.com',Editor','lastname',''$2a$10$7LRqphzDVNceXrYLrEYObuNFeDh1diiDgVXuehp3JC4ND7kv5dwVq',''ROLE_EDITOR'
        // ["ROLE_EDITOR","RESET_ANY_USER_PASSWORD","ACCESS_ADMIN_PANEL"]
        // -> [GrantedAuthority("ROLE_EDITOR"), GrantedAuthority("RESET_ANY_USER_PASSWORD"), GrantedAuthority("ACCESS_ADMIN_PANEL")]으로 변경해주어야 함

        Account account=optionalAccount.get();
        // Security가 확인 : 패스워드가 일치하면 인증 성공
        // HttpSession session = request.getSession();
        // session.setAttribute("account", account); -> Spring Security는 방식으로 진행되지 않는다


        // 권한 부여하기
        List<GrantedAuthority> grantedAuthorityList=new ArrayList<>();
        grantedAuthorityList.add(new SimpleGrantedAuthority(account.getRole()));

        for(Authority _auth :  account.getAuthorities()){
             grantedAuthorityList.add(new SimpleGrantedAuthority(_auth.getName()));
        }
        System.out.println(grantedAuthorityList.toString());
        // return 전에 패스워드 체크가 이루어짐
        // 1. 실패시 로그인 페이지로
        // 2-1. 성공시 SecurityContextHolder(Session)객체를 생성
        // 2-2. Authentication 객체를 생성하고 이 객체에 로그인 성공정보를 담아둔다.
        // return type이 UserDetails임
        // return email, pw, 권한정보
        return new User(account.getEmail(), account.getPassword(), grantedAuthorityList);
    }
}
