package com.security.jwt.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.security.jwt.model.Permission.ADMIN_CREATE;
import static com.security.jwt.model.Permission.ADMIN_DELETE;
import static com.security.jwt.model.Permission.ADMIN_READ;
import static com.security.jwt.model.Permission.ADMIN_UPDATE;
import static com.security.jwt.model.Permission.MANAGER_CREATE;
import static com.security.jwt.model.Permission.MANAGER_DELETE;
import static com.security.jwt.model.Permission.MANAGER_READ;
import static com.security.jwt.model.Permission.MANAGER_UPDATE;
import static com.security.jwt.model.Permission.VIEW_REPORTS;
import static com.security.jwt.model.Permission.ATTENDANCE_MARK;

@RequiredArgsConstructor
public enum Role implements Serializable {

  USER(Collections.emptySet()),
  ADMIN(
          Set.of(
                  ADMIN_READ,
                  ADMIN_UPDATE,
                  ADMIN_DELETE,
                  ADMIN_CREATE,
                  MANAGER_READ,
                  MANAGER_UPDATE,
                  MANAGER_DELETE,
                  MANAGER_CREATE
          )
  ),
  MANAGER(
          Set.of(
                  MANAGER_READ,
                  MANAGER_UPDATE,
                  MANAGER_DELETE,
                  MANAGER_CREATE
          )
  ),
  STUDENT(
		  Set.of(VIEW_REPORTS
				 )
  ),
  TEACHER(
		  Set.of(ATTENDANCE_MARK
				 )
		  )

  ;

  @Getter
  private final Set<Permission> permissions;

  public String getRole() {
      return this.name();
  }
  
  public List<SimpleGrantedAuthority> getAuthorities() {
    var authorities = getPermissions()
            .stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
            .collect(Collectors.toList());
    authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return authorities;
  }
}
