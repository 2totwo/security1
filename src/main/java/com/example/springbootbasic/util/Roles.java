package com.example.springbootbasic.util;
// 권한
public enum Roles {
    // USER- 메서드, USER() - 생성자 메서드
    USER("ROLE_USER"), ADMIN("ROLE_ADMIN"), EDITOR("ROLE_EDITOR");
    private String role;
    private Roles(String role){
         this.role=role;
    }
    public String getRole(){ // -> Roles.USER.getRole() : ROLE_USER
        return role;
    }
}
