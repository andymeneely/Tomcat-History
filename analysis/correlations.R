library(RODBC)
library(lattice)
conn <- odbcConnect("tomcathistory", uid="tomcathistory", pwd="tomcathistory", case="tolower")

cve <- sqlQuery(conn, "SELECT * FROM CVEResults")
files <- sqlQuery(conn, "SELECT * FROM FileResults")

# What percentage of the fixes are new code?
length(cve$FixNewCode[cve$FixNewCode=="Yes"]) / length(cve$FixNewCode)

# What percentage of the vulnerabilities were cascading?
length(cve$Cascades[cve$Cascades=="Yes"]) / length(cve$Cascades)

# What percentage of the vulnerabilities involved input validation?
length(cve$InputValidation[cve$InputValidation=="Yes"]) / length(cve$InputValidation)

# What percentage of the vulnerabilities involved output cleansing?
length(cve$OutputCleansing[cve$OutputCleansing=="Yes"]) / length(cve$OutputCleansing)

# What percentage of the vulnerabilities did not involve IO, but were better logic?
length(cve$NonIOImprovedLogic[cve$NonIOImprovedLogic=="Yes"]) / length(cve$NonIOImprovedLogic)

# What percentage of the vulnerabilities were domain specific?
length(cve$DomainSpecific[cve$DomainSpecific=="Yes"]) / length(cve$DomainSpecific)

# What percentage of the vulnerabilities were CWE Top 25?
length(cve$CWETop25[cve$CWETop25=="Yes"]) / length(cve$CWETop25)

# What percentage of the vulnerabilities were not even defined in the CWE?
length(cve$CWE[cve$CWE=="Not Defined"]) / length(cve$CWE)

# Are CWETop25 vulnerabilities statistically different than domain-specific?
table(cve$CWETop25, cve$DomainSpecific)
chisq.test(cve$CWETop25, cve$DomainSpecific)

# Do vulnerable files have more SLOC than neutral files?
## Java only
javaFiles <- sqlQuery(conn, "SELECT * FROM FileResults WHERE SLOCType='Java'")
mean(javaFiles$SLOC[javaFiles$vuln=="vulnerable"], na.rm=TRUE)
mean(javaFiles$SLOC[javaFiles$vuln=="neutral"], na.rm=TRUE)
wilcox.test(javaFiles$SLOC[javaFiles$vuln=="vulnerable"], javaFiles$SLOC[javaFiles$vuln=="neutral"])

odbcClose(conn)
rm(conn)