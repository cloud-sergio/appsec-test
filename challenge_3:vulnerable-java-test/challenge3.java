//Example case 1
String sql_query = "SELECT * FROM users WHERE userid ='"+ username + "'" + " AND password='" + Base64.getEncoder().encodeToString(passwordString.getBytes()) + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
//End of example

// Mitigating SQL Injection vulnerability:

String sql_query = "SELECT * FROM users WHERE userid =? AND password=?";
PreparedStatement prepStmt = conn.prepareStatement(sql_query);
prepStmt.setString(1, username); 
prepStmt.setString(2, Base64.getEncoder().encodeToString(passwordString.getBytes()));
prepStmt.executeUpdate();
prepStmt.close();

//Example case 2
public void postToMessageBoard(MessageBoard mb){
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	String s = br.readLine(); //VIOLATION
	mb.post(s)
}
//End of Example

// User Input Sanitization:
	try{
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String s = br.readLine(); //VIOLATION, 
		mb.post(s)
	}
	catch(Exception e){
			
	}

//Example case 3
String url = request.getParameter("hidden_url"); // not so hidden...
URL url = new URL(url); // VIOLATION 
InputStream is = url.openConnection().getContent();
//End of Example

// URL Validation
String url = request.getParameter("hidden_url"); // not so hidden...
URL url = new URL(url); // VIOLATION 
InputStream is = url.openConnection().getContent();
//Build an url validator 
//Class UrlValidator Default schemes: {https,http,ftp} 
UrlValidator urlValidator = new UrlValidator();
//perform zero trust
if (urlValidator.isValid(url) {
      URL url = new URL(url); 
      InputStream is = url.openConnection().getContent();
//	System.out.println("URL is valid");
    } else {
      	System.out.println("URL is not valid");
    }
