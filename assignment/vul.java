import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;

@WebServlet("/UserManagementServlet")
public class UserManagementServlet extends HttpServlet {

    // Handles user account creation
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // Vulnerability 1: User ID flow
        String userId = request.getParameter("userId");  // Step 1: Source
        String processedUserId = processUserId(userId);  // Step 2: Processing
        addUser(processedUserId);  // Step 3: Passing tainted data further
        
        response.getWriter().println("User ID: " + processedUserId);  // Step 5: Sink
    }

    // Vulnerability 2: User comments flow
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // Step 1: Source of user input
        String userComment = request.getParameter("comment");

        // Step 2: Process the comment and store it
        String storedComment = storeComment(userComment);

        // Step 3: Pass the comment to another method
        printComment(response, storedComment);  // Step 5: Sink
    }

    // Vulnerability 3: User search flow
    protected void searchUser(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Step 1: Source: Get the search query
        String searchQuery = request.getParameter("search");

        // Step 2: Process the query through two functions
        String validatedQuery = validateSearchQuery(searchQuery);
        String result = executeSearch(validatedQuery);

        // Step 5: Use in an unsafe context (directly in response)
        response.getWriter().println("Search result for: " + result);
    }

    // Function to process User ID (simulated for illustration)
    private String processUserId(String userId) {
        // Step 4: Weak validation (only checks for null)
        if (userId == null || userId.isEmpty()) {
            return "Invalid user ID";
        }
        return userId;  // Tainted data is returned without sanitization
    }

    // Function to add a new user (no database, for illustration purposes)
    private void addUser(String userId) {
        // In a real application, this would involve storing user data in the database
        // Here we are simulating some processing without proper sanitization
        System.out.println("Adding user with ID: " + userId);  // Internal log
    }

    // Function to store user comment (simulated for illustration)
    private String storeComment(String comment) {
        // Step 4: No sanitization applied
        return comment;
    }

    // Function to print user comment to the response (vulnerable)
    private void printComment(HttpServletResponse response, String comment) throws IOException {
        // Step 5: Sink - Untrusted input is directly printed to response
        response.getWriter().println("User Comment: " + comment);
    }

    // Validate the search query (simulated for illustration)
    private String validateSearchQuery(String query) {
        // Step 4: Check that query is alphanumeric, no sanitization applied
        if (query.matches("[a-zA-Z0-9 ]+")) {
            return query;
        } else {
            return "Invalid search query";
        }
    }

    // Execute search and return a result (simulated for illustration)
    private String executeSearch(String query) {
        // Step 4: Use the validated query in an unsafe context (pretend it's a result)
        return "Search results for: " + query;
    }
}
