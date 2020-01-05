public class AppExample {
    String appName;

    public AppExample(String appName) {
        this.appName = appName;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public void showName() {
        System.out.println("Hello my name is: " + getAppName());
    }
}
