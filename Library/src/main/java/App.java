import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

public class App {

    public static void main(String[] args) {
        Library library = new Library("../communication_Author_Library/example.app", "../communication_Author_Library", "linux");
        //library.startRegistration();
        //library.showLicenseInfo();
        //System.out.println(library.isValidAuthorPublicKey());
        System.out.println(Base64.getEncoder().encodeToString(library.getSignedAuthorPublicKey()));
    }
}
