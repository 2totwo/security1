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

     private final PasswordEncoder passwordEncoder;

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

        Optional<Account> optionalAccount=accountRepository.findOneByEmailIgnoreCase(email);
        if(!optionalAccount.isPresent()){
              throw  new UsernameNotFoundException("Account not found");
        }
        Account account=optionalAccount.get();

        // 권한 부여하기
        List<GrantedAuthority> grantedAuthorityList=new ArrayList<>();
        grantedAuthorityList.add(new SimpleGrantedAuthority(account.getRole()));

         for(Authority _auth :  account.getAuthorities()){
             grantedAuthorityList.add(new SimpleGrantedAuthority(_auth.getName()));
         }
        System.out.println(grantedAuthorityList.toString());
        return new User(account.getEmail(), account.getPassword(), grantedAuthorityList);
    }
}
