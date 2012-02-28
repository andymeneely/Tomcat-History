package edu.rit.se.history.tomcat.scrapers;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.chaoticbits.devactivity.PropsLoader;

import com.google.gdata.client.GoogleAuthTokenFactory.UserToken;
import com.google.gdata.client.authn.oauth.OAuthException;
import com.google.gdata.client.spreadsheet.SpreadsheetService;
import com.google.gdata.data.spreadsheet.SpreadsheetFeed;
import com.google.gdata.util.ServiceException;

public class GoogleDocExport {

	public static final String EXPORT_URL = "https://spreadsheets.google.com/feeds/download/spreadsheets/Export?key=@&exportFormat=csv";

	public static void main(String[] args) throws IOException, ServiceException, OAuthException {
		Properties props = PropsLoader.getProperties("tomcathistory.properties");
		SpreadsheetService service = new SpreadsheetService("RIT Software Archeology");
		service.setUserCredentials(props.getProperty("google.username"), props.getProperty("google.password"));

		UserToken docsToken = (UserToken) service.getAuthTokenFactory().getAuthToken();
		UserToken spreadsheetsToken = (UserToken) service.getAuthTokenFactory().getAuthToken();

		URL metafeedUrl = new URL(EXPORT_URL.replaceFirst("@", "0AutMI5gkPUdLdGpUY1B2Q0ZxUFpZUE1nQWRQd1VzTXc&gid=2"));
		SpreadsheetFeed feed = service.getFeed(metafeedUrl, SpreadsheetFeed.class);


//		
//		
//		InputStream inStream = null;
//		FileOutputStream outStream = null;
//
//		try {
//			inStream = ms.getInputStream();
//			outStream = new FileOutputStream(new File("c:/data/tomcat/cves.csv"));
//
//			int c;
//			while ((c = inStream.read()) != -1) {
//				outStream.write(c);
//			}
//		} finally {
//			if (inStream != null) {
//				inStream.close();
//			}
//			if (outStream != null) {
//				outStream.flush();
//				outStream.close();
//			}
//		}

		// List<SpreadsheetEntry> spreadsheets = feed.getEntries();
		// for (int i = 0; i < spreadsheets.size(); i++) {
		// SpreadsheetEntry entry = spreadsheets.get(i);
		// System.out.println("\t" + entry.getTitle().getPlainText());
		// }
	}
}
