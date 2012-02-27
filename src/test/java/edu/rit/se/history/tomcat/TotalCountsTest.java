package edu.rit.se.history.tomcat;

import static org.junit.Assert.assertEquals;

import java.sql.ResultSet;

import org.junit.BeforeClass;
import org.junit.Test;

import com.mysql.jdbc.Connection;

public class TotalCountsTest {

	private static final int TOTAL_CVES = 48;
	private static RebuildHistory history;

	@BeforeClass
	public static void initDB() throws Exception {
		history = new RebuildHistory();
		history.run(); // only if we think we need to reset
	}

	@Test
	public void groundedTheoryCounts() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM CVEGroundedTheory");
		rs.next();
		assertEquals("Grounded theory includes all CVEs", TOTAL_CVES, rs.getInt(1));
		conn.close();
	}

	@Test
	public void cvesCounts() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM CVE");
		rs.next();
		assertEquals("CVE table includes all CVEs", TOTAL_CVES, rs.getInt(1));
		conn.close();
	}

	@Test
	public void allCVEsTraced() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(DISTINCT CVE) FROM CVENonSVNFix");
		rs.next();
		assertEquals("CVE table includes all CVEs", TOTAL_CVES, rs.getInt(1));
		conn.close();
	}

	// @Test
	// public void fileCounts() throws Exception {
	// throw new IllegalStateException("unimplemented!");
	// }

	// @Test
	// public void cveResultsCounts() throws Exception {
	// throw new IllegalStateException("unimplemented!");
	// }

}
