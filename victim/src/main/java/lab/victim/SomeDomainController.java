package lab.victim;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@Controller
public class SomeDomainController {

    private static final Logger logger = LogManager.getLogger(SomeDomainController.class);

    @GetMapping("/")
    public String getAll(@RequestHeader("X-Api-Version") String apiVersion) {
        logger.info("Request for API version: {}", apiVersion);
        return "oops";
    }
}
