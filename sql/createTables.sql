DROP VIEW IF EXISTS RepoLog;
DROP TABLE IF EXISTS SVNLog;
DROP TABLE IF EXISTS SVNLogFiles;
DROP TABLE IF EXISTS Filepaths;
DROP TABLE IF EXISTS CVE;
DROP TABLE IF EXISTS CVESVNFix;
DROP TABLE IF EXISTS CVENonSVNFix;

CREATE TABLE SVNLog (
  ID int(10) unsigned NOT NULL auto_increment,
  Revision VARCHAR(20) NOT NULL,
  AuthorName varchar(45) default NULL,
  AuthorDate TIMESTAMP,
  Message longtext,
  PRIMARY KEY  (ID)
)ENGINE=MyISAM;

CREATE TABLE SVNLogFiles (
  ID int(10) unsigned NOT NULL auto_increment,
  Revision VARCHAR(20) NOT NULL,
  Filepath varchar(500) NOT NULL,
  Action varchar(1),
  NumChanges int(10) unsigned,
  LinesInserted int(10) unsigned,
  LinesDeleted int(10) unsigned,
  LinesNew int(10) unsigned,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM;

CREATE VIEW RepoLog AS
	SELECT l.id, l.revision, l.authorname, l.authordate, l.message, lf.filepath, lf.Action 
	FROM SVNLog l, SVNLogFiles lf
  		WHERE lf.revision=l.revision;

CREATE TABLE CVE (
  ID int(10) unsigned NOT NULL auto_increment,
  CVE VARCHAR(15) NOT NULL,
  CWE INTEGER NOT NULL,
  CVSS DOUBLE NOT NULL,
  ConfidentialityImpact VARCHAR(10) NOT NULL,
  IntegrityImpact VARCHAR(10) NOT NULL,
  AuthRequired VARCHAR(100) NOT NULL,
  GainedAccess VARCHAR(10) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM;

CREATE TABLE CVESVNFix (
  ID int(10) unsigned NOT NULL auto_increment,
  CVE VARCHAR(15) NOT NULL,
  SVNRevision INTEGER NOT NULL,
  TomcatRelease VARCHAR(5) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM;

CREATE TABLE CVENonSVNFix (
  ID int(10) unsigned NOT NULL auto_increment,
  CVE VARCHAR(15) NOT NULL,
  Filepath varchar(500) NOT NULL,
  TomcatRelease VARCHAR(5) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM;

CREATE TABLE Filepaths (
  ID int(10) unsigned NOT NULL auto_increment,
  Filepath varchar(500) NOT NULL,
  TomcatRelease varchar(5) NOT NULL,
  PRIMARY KEY  (`ID`)
) ENGINE=MyISAM;