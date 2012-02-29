DROP VIEW IF EXISTS CVEResults;

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
