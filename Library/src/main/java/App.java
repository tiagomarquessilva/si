public class App {

    public static void main(String[] args) {

        AppExample app = new AppExample("Securissimo");
        Library licenseControl = new Library("./src/main/java/AppExample.java", "../communication_Author_Library", "linux");
        while (!licenseControl.isRegistered()) {
            licenseControl.startRegistration();
            licenseControl.showLicenseInfo();
        }
        app.getAppName();
    }
}
