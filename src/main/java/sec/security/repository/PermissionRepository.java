package sec.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import sec.security.model.Permission;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Permission findByPermission(String permission);
}
