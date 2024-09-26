package org.example.injectionsqlexample.model;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Entity
@Table(name = "person")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty(message = "Username is required")
    @Size(min = 3, max = 500, message = "Username must be between 3 and 20 characters")
    private String username;

    @NotEmpty(message = "Password is required")
    private String password;


}
