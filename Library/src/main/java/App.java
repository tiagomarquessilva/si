public class App {
    public static void main(String[] args) {
        Library library = new Library("pom.xml", "../communication_Author_Library");
        library.startRegistration();
        library.showLicenseInfo();
    }
}
