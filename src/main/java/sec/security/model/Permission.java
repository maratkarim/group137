package sec.security.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Getter
@Setter
@Table(name = "t_permission")
public class Permission extends BaseEntity implements GrantedAuthority {

    private String permission; //ROLE_USER

    @Override
    public String getAuthority() {
        return permission;
    }
}
