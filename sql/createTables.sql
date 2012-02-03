DROP VIEW IF EXISTS RepoLog;
DROP TABLE IF EXISTS SVNLog;
DROP TABLE IF EXISTS SVNLogFiles;

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