package com.example.springbootbasic.repository;

import com.example.springbootbasic.entiry.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {

    // 쿼리 메서드
    Optional<Account> findOneByEmailIgnoreCase(String email);

}
