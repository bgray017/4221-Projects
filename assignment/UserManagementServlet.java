import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;

@WebServlet("/UserManagementServlet")
public class UserManagementServlet extends HttpServlet {

    // Handles user account creation
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Vulnerability 1: User ID flow
        String userId = request.getParameter("userId"); // Step 1: Source
        String processedUserId = processUserId(userId); // Step 2: Processing
        addUser(processedUserId); // Step 3: Passing tainted data further

        // Sanitize output using OWASP Encoder
        response.getWriter().println("User ID: " + Encode.forHtml(processedUserId)); // Step 5: Sink
    }

    // Vulnerability 2: User comments flow
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Step 1: Source of user input
        String userComment = request.getParameter("comment");

        // Step 2: Process the comment and store it
        String storedComment = storeComment(userComment);

        // Step 3: Pass the comment to another method
        printComment(response, storedComment); // Step 5: Sink
    }

    // Vulnerability 3: User search flow
    protected void searchUser(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Step 1: Source: Get the search query
        String searchQuery = request.getParameter("search");

        // Step 2: Process the query through two functions
        String validatedQuery = validateSearchQuery(searchQuery);
        String result = executeSearch(validatedQuery);

        // Sanitize output before displaying result
        response.getWriter().println("Search result for: " + Encode.forHtml(result)); // Step 5: Sink
    }

    // Function to process User ID (simulated for illustration)
    private String processUserId(String userId) {
        if (userId == null || userId.isEmpty()) {
            return "Invalid user ID";
        }
        // Sanitize and validate user ID
        userId = userId.trim();
        if (!userId.matches("^[a-zA-Z0-9_-]{3,32}$")) {
            throw new IllegalArgumentException("Invalid user ID format");
        }
        return StringEscapeUtils.escapeHtml4(userId); // Step 4: Return sanitized userId
    }

    // Function to add a new user (no database, for illustration purposes)
    private void addUser(String userId) {
        // Sanitized userId is now safe to use
        System.out.println("Adding user with ID: " + userId); // Internal log
    }

    // Function to store user comment (simulated for illustration)
    private String storeComment(String comment) {
        if (comment == null || comment.isEmpty()) {
            return "";
        }
        // Sanitize comment before storage
        return StringEscapeUtils.escapeHtml4(comment); // Step 4: Sanitize comment
    }

    // Function to print user comment to the response (vulnerable)
    private void printComment(HttpServletResponse response, String comment) throws IOException {
        // Step 5: Sink - Sanitized input is directly printed to response
        response.getWriter().println("User Comment: " + Encode.forHtml(comment)); // Safe output
    }

    // Validate the search query (simulated for illustration)
    private String validateSearchQuery(String query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        // Strict input validation
        if (!query.matches("^[a-zA-Z0-9\\s]{1,100}$")) {
            throw new IllegalArgumentException("Invalid search query format");
        }
        return StringEscapeUtils.escapeHtml4(query); // Step 4: Sanitize validated query
    }

    // Execute search and return a result (simulated for illustration)
    private String executeSearch(String query) {
        // Query is already sanitized and validated
        return "Search results for: " + query; // Step 4: Return sanitized result
    }
}
