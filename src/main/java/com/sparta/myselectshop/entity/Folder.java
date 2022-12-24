package com.sparta.myselectshop.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@NoArgsConstructor
public class Folder {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private String name;

    @ManyToOne
    @JoinColumn(name = "USER_ID", nullable = false)     // name = 외래키 명칭
    private User user;

    public Folder(String name, User user) {
        this.name = name;
        this.user = user;
    }
}