package edu.rit.se.history.tomcat;

import static org.junit.Assert.assertEquals;

import java.sql.ResultSet;

import org.junit.BeforeClass;
import org.junit.Test;

import com.mysql.jdbc.Connection;

public class TotalCountsTest {

	private static final int TOTAL_CVES = 52;
	private static RebuildHistory history;

	@BeforeClass
	public static void initDB() throws Exception {
		history = new RebuildHistory();
//		history.run(); // only if we think we need to reset
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
	public void cveAnalysisCounts() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM CVEResults");
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

	@Test
	public void vulnerableFilesAtReleaseAccountedFor() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM cvenonsvnfix WHERE filepath NOT IN (SELECT filepath FROM filepaths)");
		rs.next();
		int actualCount = rs.getInt(1);
		conn.close();
		assertEquals("Only five files were added post-release", 5, actualCount);

		// Query to debug this one:
		// SELECT * FROM CVENonSVNFix cf LEFT OUTER JOIN Filepaths f ON cf.filepath=f.filepath ORDER BY
		// cf.cve ASC
		// Another query to debug:
		// SELECT cve,filepath FROM cvenonsvnfix WHERE filepath NOT IN (SELECT filepath FROM filepaths)

		// Files added post-release:
		// * container/catalina/src/share/org/apache/catalina/util/ExpiringCache.java

		// Fixed in trunk, but not found in the 5.5 release, so we're ignoring it
		// * connectors/jk/java/org/apache/jk/common/ChannelNioSocket.java

		// Some other stuff related to AbstractAprProcessor were refactorings after the fact (pulling out
		// abstraction) - those were ignored

	}

	@Test
	public void allSLOCAccountedFor() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery(
				"SELECT COUNT(*) FROM filepaths WHERE SLOC IS NULL AND (Filepath LIKE '%.java' OR Filepath LIKE '%.c' OR Filepath LIKE '%.h')");
		rs.next();
		int actualCount = rs.getInt(1);
		conn.close();
		assertEquals("Only three file were added post-release", 3, actualCount);
		// Query to debug this one:
		// SELECT * FROM filepaths WHERE SLOC IS NULL AND (Filepath LIKE '%.java' OR Filepath LIKE '%.c' OR
		// Filepath LIKE '%.h')
	}

	@Test
	public void allCVESInFixes() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(DISTINCT CVE) FROM CVEFixResults");
		rs.next();
		int actualCount = rs.getInt(1);
		conn.close();
		assertEquals("All CVEs accounted for", TOTAL_CVES, actualCount);
	}

	@Test
	public void allCVEsHaveAFilepath() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM cve WHERE cve.cve NOT IN (SELECT CVE FROM CVEFixResults)");
		rs.next();
		int actualCount = rs.getInt(1);
		conn.close();
		assertEquals("All CVEs accounted for", 0, actualCount);
	}

	@Test
	public void oneFilepathDistinctlyPerCVE() throws Exception {
		Connection conn = history.getDbUtil().getConnection();
		ResultSet rs = conn.createStatement().executeQuery(
				"SELECT COUNT(*) FROM (SELECT Filepath,CVE,Count(*) NUM FROM CVENonSVNFix  GROUP BY Filepath, CVE HAVING NUM > 1) X");
		rs.next();
		int actualCount = rs.getInt(1);
		conn.close();
		assertEquals("No situations where we have filepaths counted more than once on a given CVE", 0, actualCount);
		// Query to debug:
		// SELECT Filepath,CVE,Count(*) NUM FROM CVENonSVNFix GROUP BY Filepath, CVE HAVING NUM > 1
	}
}
