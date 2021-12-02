package com.olx.entity;

import com.olx.utils.ActiveStateEnum;

import javax.persistence.*;

@Entity(name = "USERS")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;

    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "role")
    private final String role = "ROLE_USER";

    @Enumerated(value = EnumType.ORDINAL)
    @Column(name = "active")
    private ActiveStateEnum active = ActiveStateEnum.FALSE;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email")
    private String email;

    public UserEntity() {

    }

    public UserEntity(String email, String username, String firstName, String lastName, String password, ActiveStateEnum active) {
        this.email = email;
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.active = active;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public ActiveStateEnum isActive() {
        return active;
    }

    public void setActive(ActiveStateEnum active) {
        this.active = active;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "email='" + email + '\'' +
                ", username='" + username + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", password='" + password + '\'' +
                ", active='" + active.state + '\'' +
                '}';
    }
}
