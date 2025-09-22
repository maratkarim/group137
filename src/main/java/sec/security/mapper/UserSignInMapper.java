package sec.security.mapper;

import org.mapstruct.Mapper;
import sec.security.dto.UserDto;
import sec.security.dto.UserSignInDto;
import sec.security.model.User;

@Mapper(componentModel = "spring")
public interface UserSignInMapper {

    User toEntity(UserSignInDto userSignInDto);

}
