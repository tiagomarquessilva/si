import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

public class App {
    public static void main(String[] args) {
        Author a = new Author("../communication_Author_Library", "database/database.db", new String[]{"../communication_Author_Library/example.app"}, 8760, "pwd");
        //a.init();
        a.start();
    }
}
