import java.sql.Connection;
import java.sql.Statement;

public class VulnExample {
    public void badSql(Connection conn, String userInput) throws Exception {
        // SQL Injection via string concatenation
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM users WHERE id = '" + userInput + "'");
    }

    public void commandInjection(String input) throws Exception {
        // OS Command Injection
        Runtime.getRuntime().exec("ls " + input);
    }
}
