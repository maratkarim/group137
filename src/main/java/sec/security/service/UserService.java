package sec.security.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import sec.security.dto.SetAdminDto;
import sec.security.dto.UserDto;
import sec.security.dto.UserSignInDto;
import sec.security.model.User;

public interface UserService extends UserDetailsService {
    Boolean signUp(String email, String password, String repeatPassword, String fullName);
    Boolean updatePassword(String oldPassword, String newPassword, String repeatNewPassword);

    Boolean signUpRest(UserDto userDto);
    Boolean signInRest(UserSignInDto userSignInDto);
    Boolean setRole(SetAdminDto email);

}
