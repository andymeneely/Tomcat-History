package edu.rit.se.history.tomcat.filter;

import java.io.File;
import java.io.FileNotFoundException;
import java.sql.SQLException;
import java.util.Scanner;

import org.chaoticbits.devactivity.DBUtil;

import com.mysql.jdbc.Connection;

public class FilepathFilters {

	public void filter(DBUtil dbUtil, File filterlist) throws FileNotFoundException, SQLException {
		Scanner scanner = new Scanner(filterlist);
		Connection conn = dbUtil.getConnection();
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine().trim();
			if (line.startsWith("#") || line.length() == 0)
				continue;
			conn.createStatement().executeUpdate("DELETE FROM Filepaths WHERE Filepath LIKE '" + line + "'");
		}
		conn.close();
		scanner.close();
	}
}
