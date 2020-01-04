import java.security.Provider;
import java.security.Security;

public class App {
    public static void main(String[] args) {
        Library library = new Library("../communication_Author_Library/example.app", "../communication_Author_Library", "linux");
        //library.init();
        //library.startRegistration();
        library.showLicenseInfo();
        System.out.println(library.isValidAuthorPublicKey());
    }
}
