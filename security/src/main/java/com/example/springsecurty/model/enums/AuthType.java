package com.example.springsecurty.model.enums;

public enum AuthType{
    ADMIN, USER;

    public String toString(){
        return name();
    }
}