package sec.security.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import sec.security.dto.UserDto;
import sec.security.model.User;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto toDto(User user);

    User toEntity(UserDto dto);

    List<UserDto> toDtoList(List<User> userList);

}
