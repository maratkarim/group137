package sec.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import sec.security.service.UserService;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/sign-up")
    @PreAuthorize("isAnonymous()")
    public String signUpPage(Model model){
        return "sign-up";
    }

    @PostMapping("/registration")
    @PreAuthorize("isAnonymous()")
    public String registration(@RequestParam(name = "user_email") String email,
                               @RequestParam(name = "user_password") String newPassword,
                               @RequestParam(name = "user_repeat_password") String repeatPassword,
                               @RequestParam(name = "user_full_name") String fullName){
        userService.signUp(email, newPassword, repeatPassword, fullName);
        return "redirect:/sign-up?success";
    }

    @GetMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    public String changePassword(Model model){
        return "change-password";
    }

    @PostMapping("/save-password")
    @PreAuthorize("isAuthenticated()")
    public String savePassword(@RequestParam(name = "user_old_password") String oldPassword,
                               @RequestParam(name = "user_new_password") String newPassword,
                               @RequestParam(name = "user_repeat_new_password") String repeatNewPassword){
        Boolean result = userService.updatePassword(oldPassword, newPassword, repeatNewPassword);

        if(result != null){
            if(result){
                return "redirect:/change-password?success";
            }

            return "redirect:/change-password?newPasswordError";
        }

        return "redirect:/change-password?oldPasswordError";
    }

    @GetMapping("/sign-in")
    @PreAuthorize("isAnonymous()")
    public String signIn(Model model){
        return "sign-in";
    }

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public String profile(Model model){
        return "profile";
    }





    @GetMapping("/admin-page")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminPage(){
        return "admin-page";
    }

    @GetMapping("/user-page")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String userPage(){
        return "user-page";
    }

}
