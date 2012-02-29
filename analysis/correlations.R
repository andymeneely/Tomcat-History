library(RODBC)
library(lattice)
conn <- odbcConnect("tomcathistory", uid="tomcathistory", pwd="tomcathistory", case="tolower")

cve <- sqlQuery(conn, "SELECT * FROM CVEResults")

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

# Are CWETop25 vulnerabilities statistically different than domain-specific?
table(cve$CWETop25, cve$DomainSpecific)
chisq.test(cve$CWETop25, cve$DomainSpecific)

#AllCounts <- sqlQuery(conn, "SELECT * FROM AllCounts")
#histogram(~AllCounts$NumDevs | AllCounts$HadVulns, type="count", col="red", main="Vulnerable NumDevs", freq=TRUE, xlab="Number of Developers")
#wilcox.test(AllCounts$NumDevs[AllCounts$HadVulns=="neutral"], AllCounts$NumDevs[AllCounts$HadVulns=="neutral"])

odbcClose(conn)
rm(conn)