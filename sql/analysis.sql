DROP VIEW IF EXISTS CVEResults;
DROP VIEW IF EXISTS FileResults;

CREATE VIEW CVEResults AS 
	SELECT 	c.CVE, 
			c.Tomcat55,
			c.Tomcat6,
			c.Tomcat7,
			c.CWE,
			c.CWETop25,
			c.CVSS,
			c.ConfidentialityImpact,
			c.AvailabilityImpact,
			c.AccessComplexity,
			c.AuthRequired,
			c.GainedAccess,
			cg.FixNewCode,
			cg.Cascades,
			cg.InputValidation,
			cg.OutputCleansing,
			cg.NonIOImprovedLogic,
			cg.DomainSpecific
	FROM CVE c INNER JOIN CVEGroundedTheory cg ON (c.cve=cg.cve)
;

CREATE VIEW FileResults AS 
	SELECT  f.filepath,
        f.TomcatRelease, 
        f.SLOCType, 
        f.SLOC,
        IF(cf.CVE IS NULL, 'neutral','vulnerable') vuln
	FROM (filepaths f LEFT OUTER JOIN CVENonSVNFix cf ON (f.filepath=cf.filepath))
;
