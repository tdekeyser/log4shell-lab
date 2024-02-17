package lab.victim;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    private static final Logger logger = LogManager.getLogger(LoginController.class);

    @GetMapping("/")
    public String home(@RequestHeader("User-Agent") String userAgent) {
        logger.info("Device access: {}", userAgent);

        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username) {
        if (username != "admin") {
            logger.error("Unauthorized username '{}' tried logging in", username);
        }

        return "login";
    }

}
