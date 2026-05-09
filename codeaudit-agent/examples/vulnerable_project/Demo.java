import java.io.ObjectInputStream;
import java.sql.Statement;

public class Demo {
    private static final String PASSWORD = "hardcoded-password-demo";

    public void find(Statement statement, String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        statement.execute(sql);
    }

    public void command(String input) throws Exception {
        Runtime.getRuntime().exec("sh -c " + input);
    }

    public Object deserialize(ObjectInputStream in) throws Exception {
        return in.readObject();
    }

    public void noisy() {
        System.out.println("hello");
    }
}
