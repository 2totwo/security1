package com.example.springbootbasic.entiry;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Setter
@Getter
@NoArgsConstructor
@Entity
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String password;
    private String firstname;
    private String lastname;

    private String role;

    @OneToMany(mappedBy = "account")
    private List<Post> posts;

    // M:N의 관계는 테이블이 필요하므로 JoinTable
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
           name = "account_authority",
           joinColumns = {@JoinColumn(name = "account_id", referencedColumnName = "id")},
           inverseJoinColumns = {@JoinColumn(name = "authority_id", referencedColumnName = "id")}
    )
    private Set<Authority> authorities=new HashSet<>();
}
