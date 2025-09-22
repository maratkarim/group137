package sec.security.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sec.security.dto.SetAdminDto;
import sec.security.dto.UserDto;
import sec.security.dto.UserSignInDto;
import sec.security.mapper.UserMapper;
import sec.security.mapper.UserSignInMapper;
import sec.security.model.Permission;
import sec.security.model.User;
import sec.security.repository.PermissionRepository;
import sec.security.repository.UserRepository;
import sec.security.service.UserService;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private UserSignInMapper userSignInMapper;

    @Override
    public Boolean signUp(String email, String password, String repeatPassword, String fullName) {

        User u = userRepository.findByEmail(email);

        if (Objects.isNull(u)){

            if (password.equals(repeatPassword)){

                List<Permission> permissions = new ArrayList<>();
                Permission simplePermission = permissionRepository.findByPermission("ROLE_USER");
                permissions.add(simplePermission);

                User user = new User();
                user.setPassword(passwordEncoder.encode(repeatPassword));
                user.setEmail(email);
                user.setFullName(fullName);
                user.setRoles(permissions);

                userRepository.save(user);

                return true;
            }
            return false;
        }
        return null;
    }

    @Override
    public Boolean signUpRest(UserDto userDto) {

        User user = userMapper.toEntity(userDto);

        User signUser = userRepository.findByEmail(user.getEmail());

        if (Objects.isNull(signUser)){
            if (user.getPassword().equals(userDto.getRepeatPassword())){

                List<Permission> permissions = new ArrayList<>();
                Permission simplePermission = permissionRepository.findByPermission("ROLE_USER");
                permissions.add(simplePermission);

                User user1 = new User();
                user.setPassword(passwordEncoder.encode(userDto.getRepeatPassword()));
                user.setEmail(user.getEmail());
                user.setFullName(user.getFullName());
                user.setRoles(permissions);

                userRepository.save(user);

                return true;
            }
            return false;
        }
        return null;
    }

    @Override
    public Boolean signInRest(UserSignInDto userSignInDto) {

        User user = userSignInMapper.toEntity(userSignInDto);

        if (Objects.nonNull(user)){
            User login = userRepository.findByEmail(user.getEmail());
            if (passwordEncoder.matches(userSignInDto.getPassword(),login.getPassword())){
                return true;
            }
            return false;
        }
        return false;
    }


    @Override
    public Boolean updatePassword(String oldPassword, String newPassword, String repeatNewPassword) {

        User u = getCurrentUser();

        if (Objects.nonNull(u)){
            if (passwordEncoder.matches(oldPassword, u.getPassword())){
                if (newPassword.equals(repeatNewPassword)){
                    u.setPassword(passwordEncoder.encode(newPassword));
                    userRepository.save(u);
                    return true;
                }
                return false;
            }
            return null;
        }
        return null;
    }

    @Override
    public Boolean setRole(SetAdminDto email){
        User user = userRepository.findByEmail(email.getEmail());

        if (Objects.nonNull(user)) {
            List<Permission> permissions = new ArrayList<>();
            Permission permission = permissionRepository.findByPermission("ROLE_ADMIN");
            permissions.add(permission);
            user.setRoles(permissions);
            userRepository.save(user);
            return true;
        }
        return false;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);

        if(Objects.nonNull(user)){
            return user;
        }

        throw new UsernameNotFoundException("User Not Found");
    }

    private User getCurrentUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User user = (User) authentication.getPrincipal();
            return user;
        }

        return null;
    }
}
