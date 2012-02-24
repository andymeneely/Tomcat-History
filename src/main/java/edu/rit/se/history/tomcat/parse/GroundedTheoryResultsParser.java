package edu.rit.se.history.tomcat.parse;

import java.io.File;
import java.io.FileReader;
import java.sql.PreparedStatement;

import org.chaoticbits.devactivity.DBUtil;

import au.com.bytecode.opencsv.CSVReader;

import com.mysql.jdbc.Connection;

public class GroundedTheoryResultsParser {

	public void parse(DBUtil dbUtil, File csv) throws Exception {
		Connection conn = dbUtil.getConnection();
		PreparedStatement ps = conn
				.prepareStatement("INSERT INTO CVEGroundedTheory(CVE,FixNewCode,Cascades,InputValidation,OutputCleansing,NonIOImprovedLogic, DomainSpecific) "
						+ "VALUES (?,?,?,?,?,?,?)");
		String line[];
		CSVReader reader = new CSVReader(new FileReader(csv));
		reader.readNext(); // skip the header
		while ((line = reader.readNext()) != null) {
			if (line.length < 5)
				continue;
			ps.setString(1, line[0]); // CVE
			ps.setString(2, line[1]); // FixNewCode
			ps.setString(3, line[2]); // Cascades
			ps.setString(4, includes(line[3], "Input")); // InputValidation
			ps.setString(5, includes(line[3], "Output")); // OutputCleansing
			ps.setString(6, includes(line[3], "Better Logic")); // NonIOImprovedLogic
			ps.setString(7, line[4]); // DomainSpecific
			ps.addBatch();
		}
		ps.executeBatch();
		conn.close();
	}

	private String includes(String string, String substring) {
		return string.contains(substring) ? "Yes" : "No";
	}

}
