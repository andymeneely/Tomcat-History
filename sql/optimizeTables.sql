CREATE UNIQUE INDEX CVEIndex USING BTREE ON CVE(CVE);
CREATE UNIQUE INDEX CVEGroundedTheoryIndex USING BTREE ON CVEGroundedTheory(CVE);
CREATE INDEX CVENonSVNFixIndex USING BTREE ON CVENonSVNFix(CVE);
CREATE INDEX FilepathIndex USING BTREE ON Filepaths(Filepath);

OPTIMIZE TABLE SVNLog;
OPTIMIZE TABLE SVNLogFiles;
OPTIMIZE TABLE Filepaths;
OPTIMIZE TABLE CVE;
OPTIMIZE TABLE CVESVNFix;
OPTIMIZE TABLE CVENonSVNFix;
OPTIMIZE TABLE CVEGroundedTheory;