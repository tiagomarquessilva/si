import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

public class App {
    public static void main(String[] args) {
        Author a = new Author("../communication_Author_Library", "database/database.db", 8760, "password");
        a.init();
        a.start();
    }
}
