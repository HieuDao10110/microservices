package com.example.authservice.model;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Collection;

@Entity
@Getter
@NoArgsConstructor
public class Privilege {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    @ManyToMany(mappedBy = "privileges")
    private Collection<Role> roles;

    public Privilege(String name){
        this.name = name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setRoles(Collection<Role> roles) {
        this.roles = roles;
    }
}
