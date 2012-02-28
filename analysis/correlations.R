library(RODBC)
library(lattice)
conn <- odbcConnect("tomcathistory", uid="tomcathistory", pwd="tomcathistory", case="tolower")

#AllCounts <- sqlQuery(conn, "SELECT * FROM AllCounts")
#histogram(~AllCounts$NumDevs | AllCounts$HadVulns, type="count", col="red", main="Vulnerable NumDevs", freq=TRUE, xlab="Number of Developers")
#wilcox.test(AllCounts$NumDevs[AllCounts$HadVulns=="neutral"], AllCounts$NumDevs[AllCounts$HadVulns=="neutral"])

odbcClose(conn)
rm(conn)