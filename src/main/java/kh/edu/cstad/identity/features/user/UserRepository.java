package kh.edu.cstad.identity.features.user;

import kh.edu.cstad.identity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository  extends JpaRepository<User,Long> {

    Optional<User>findByUsername(String username);

}
