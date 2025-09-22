package sec.security.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sec.security.dto.SetAdminDto;
import sec.security.dto.UserDto;
import sec.security.dto.UserSignInDto;
import sec.security.model.User;
import sec.security.service.UserService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/rest")
public class UserRestController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/registration")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<?> registr(@RequestBody UserDto userDto){
        return userService.signUpRest(userDto) ? ResponseEntity.ok().build()
                : ResponseEntity.badRequest().build();
    }

    @PostMapping("/login")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<?> login(@RequestBody UserSignInDto dto, HttpServletRequest req) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getEmail(), dto.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        req.getSession(true); // создаёт JSESSIONID
        return ResponseEntity.ok().build();
    }

    @PostMapping("/setAdmin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> setAdmin(@RequestBody SetAdminDto email){
        return userService.setRole(email) ? ResponseEntity.ok().build()
                : ResponseEntity.badRequest().build();
    }
}














