package com.example.identity_service.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Short id;

    /** Stored without the "ROLE_" prefix, e.g. "USER", "ADMIN". */
    @EqualsAndHashCode.Include
    @Column(nullable = false, unique = true, length = 50)
    @Enumerated(EnumType.STRING)
    private RoleEnum name;
}
