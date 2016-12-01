/*
SQLyog Ultimate v11.27 (32 bit)
MySQL - 5.7.15-log : Database - myauth
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`myauth` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `myauth`;

/*Table structure for table `t_auth_def_conf` */

DROP TABLE IF EXISTS `t_auth_def_conf`;

CREATE TABLE `t_auth_def_conf` (
  `USER_ID` char(8) NOT NULL COMMENT '参照用户表',
  `SYS_SN` int(11) NOT NULL COMMENT '参照系统配置表',
  `CREATE_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '配置创建的时间，取值系统时间',
  `DEFAULT_AUTH_TIME` smallint(6) DEFAULT NULL COMMENT '默认情况下，若用户申请授权时，不输入授权时长参数，那么系统级按照此默认设置进行授权，但是不能超过用户级设置',
  PRIMARY KEY (`USER_ID`,`SYS_SN`),
  KEY `RELATIONSHIP_3_FK` (`SYS_SN`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk COMMENT='授权预定义表';

/*Table structure for table `t_req_auth_log` */

DROP TABLE IF EXISTS `t_req_auth_log`;

CREATE TABLE `t_req_auth_log` (
  `REQ_SN` mediumint(6) NOT NULL AUTO_INCREMENT COMMENT '授权/解授权请求序列号，系统自动生成',
  `REQ_TIME` datetime NOT NULL COMMENT '请求时间',
  `CLIENT_IP` varchar(19) NOT NULL,
  `CLIENT_PORT` mediumint(6) NOT NULL,
  `USER_ID` char(8) NOT NULL COMMENT '参照用户表',
  `SYS_ID` varchar(50) NOT NULL,
  `REQ_CO_TIME` mediumint(6) NOT NULL COMMENT '单位：分钟',
  `REQ_TYPE` char(1) NOT NULL DEFAULT '1' COMMENT '授权1，解授权0',
  `PROCESS_FLAG` char(1) NOT NULL DEFAULT '0' COMMENT '0-申请，1-授权实现，2-授权回收',
  `OS_TYPE` varchar(100) DEFAULT NULL,
  `OS_USER` varchar(100) DEFAULT NULL,
  `OS_HOSTNAME` varchar(100) DEFAULT NULL,
  `OS_MAC` varchar(100) DEFAULT NULL,
  `JAR_MD5` varchar(100) DEFAULT NULL,
  KEY `REQ_SN` (`REQ_SN`)
) ENGINE=InnoDB AUTO_INCREMENT=5146 DEFAULT CHARSET=gbk COMMENT='用户请求授权日志';

/*Table structure for table `t_req_auth_log_his` */

DROP TABLE IF EXISTS `t_req_auth_log_his`;

CREATE TABLE `t_req_auth_log_his` (
  `REQ_SN` mediumint(6) NOT NULL DEFAULT '0' COMMENT '授权/解授权请求序列号，系统自动生成',
  `REQ_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '请求时间',
  `CLIENT_IP` varchar(19) NOT NULL,
  `CLIENT_PORT` mediumint(6) NOT NULL,
  `USER_ID` char(8) NOT NULL COMMENT '参照用户表',
  `SYS_ID` varchar(50) NOT NULL,
  `REQ_CO_TIME` mediumint(6) NOT NULL COMMENT '单位：分钟',
  `REQ_TYPE` char(1) NOT NULL DEFAULT '1' COMMENT '授权1，解授权0',
  `PROCESS_FLAG` char(1) NOT NULL DEFAULT '0' COMMENT '0-申请，1-授权实现，2-授权回收',
  `INSERT_DT` datetime DEFAULT CURRENT_TIMESTAMP,
  `OS_TYPE` varchar(100) DEFAULT NULL,
  `OS_USER` varchar(100) DEFAULT NULL,
  `OS_HOSTNAME` varchar(100) DEFAULT NULL,
  `OS_MAC` varchar(100) DEFAULT NULL,
  `JAR_MD5` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=gbk;

/*Table structure for table `t_sys_conf` */

DROP TABLE IF EXISTS `t_sys_conf`;

CREATE TABLE `t_sys_conf` (
  `SYS_SN` int(11) NOT NULL COMMENT '1,2,3，。。。',
  `SYS_ID` varchar(50) NOT NULL COMMENT '系统ID，比如HXPIS,用户定义',
  `SYS_DESC` varchar(200) DEFAULT NULL COMMENT '系统中文描述',
  `SYS_IP` varchar(15) DEFAULT NULL COMMENT '系统访问URL的IP',
  `SYS_PORT` mediumint(6) DEFAULT NULL COMMENT '系统访问端口',
  `SYS_URL` varchar(250) DEFAULT NULL COMMENT '系统访问完整的URL',
  `SYS_STATUS` char(1) DEFAULT NULL COMMENT '系统可用状态，0-可用，1-不可用',
  PRIMARY KEY (`SYS_SN`,`SYS_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk COMMENT='系统配置表';

/*Table structure for table `t_sys_log` */

DROP TABLE IF EXISTS `t_sys_log`;

CREATE TABLE `t_sys_log` (
  `LOG_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `LOG_TYPE` char(4) NOT NULL COMMENT '0101-登录，0102-退出，0201-授权申请，0202-解授权申请，0203-系统授权实现，0204-系统解授权',
  `CLIENT_IP` varchar(15) NOT NULL,
  `CLIENT_PORT` mediumint(6) NOT NULL,
  `USER_ID` char(50) DEFAULT NULL,
  `LOG_MSG` varchar(500) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='日志表';

/*Table structure for table `t_user_conf` */

DROP TABLE IF EXISTS `t_user_conf`;

CREATE TABLE `t_user_conf` (
  `USER_ID` char(8) NOT NULL COMMENT '用户ID,使用公司的员工ID',
  `AUTH_KEY` varchar(32) DEFAULT NULL COMMENT '认证码，即密码',
  `MAX_TIME` smallint(6) DEFAULT NULL COMMENT '用户级别授权时长控制，授权申请不能超过此设定',
  `USER_NAME` varchar(50) DEFAULT NULL COMMENT '用户中文名描述',
  `USER_STATUS` char(1) DEFAULT NULL COMMENT '0：有效，1：无效',
  `CORP_EMAIL` varchar(100) DEFAULT NULL,
  `COMMENT_TEXT` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk COMMENT='用户配置表';

/*Table structure for table `t_user_hostname_regited` */

DROP TABLE IF EXISTS `t_user_hostname_regited`;

CREATE TABLE `t_user_hostname_regited` (
  `user_id` varchar(8) NOT NULL,
  `host_name` varchar(100) NOT NULL,
  `os_mac` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Table structure for table `user_upload` */

DROP TABLE IF EXISTS `user_upload`;

CREATE TABLE `user_upload` (
  `username` varchar(50) DEFAULT NULL,
  `addr` varchar(200) DEFAULT NULL,
  `gender` char(2) DEFAULT NULL,
  `telphoneno` char(15) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

/*Table structure for table `v_authed` */

DROP TABLE IF EXISTS `v_authed`;

/*!50001 DROP VIEW IF EXISTS `v_authed` */;
/*!50001 DROP TABLE IF EXISTS `v_authed` */;

/*!50001 CREATE TABLE  `v_authed`(
 `USER_NAME` varchar(50) ,
 `USER_ID` char(8) ,
 `OS_HOSTNAME` varchar(100) ,
 `COUNT(*)` bigint(21) 
)*/;

/*Table structure for table `v_authing` */

DROP TABLE IF EXISTS `v_authing`;

/*!50001 DROP VIEW IF EXISTS `v_authing` */;
/*!50001 DROP TABLE IF EXISTS `v_authing` */;

/*!50001 CREATE TABLE  `v_authing`(
 `USER_NAME` varchar(50) ,
 `USER_ID` char(8) ,
 `SYS_DESC` varchar(200) ,
 `OS_HOSTNAME` varchar(100) ,
 `client_ip` varchar(19) ,
 `OS_MAC` varchar(100) ,
 `JAR_MD5` varchar(100) 
)*/;

/*View structure for view v_authed */

/*!50001 DROP TABLE IF EXISTS `v_authed` */;
/*!50001 DROP VIEW IF EXISTS `v_authed` */;

/*!50001 CREATE ALGORITHM=UNDEFINED DEFINER=`autho`@`%` SQL SECURITY DEFINER VIEW `v_authed` AS select `u`.`USER_NAME` AS `USER_NAME`,`t`.`USER_ID` AS `USER_ID`,`t`.`OS_HOSTNAME` AS `OS_HOSTNAME`,count(0) AS `COUNT(*)` from (`t_req_auth_log_his` `t` left join `t_user_conf` `u` on((`t`.`USER_ID` = `u`.`USER_ID`))) where ((`t`.`OS_HOSTNAME` is not null) and (not((`t`.`OS_MAC` like '00-%')))) group by `u`.`USER_NAME`,`t`.`USER_ID`,`t`.`OS_HOSTNAME` order by `t`.`USER_ID` */;

/*View structure for view v_authing */

/*!50001 DROP TABLE IF EXISTS `v_authing` */;
/*!50001 DROP VIEW IF EXISTS `v_authing` */;

/*!50001 CREATE ALGORITHM=UNDEFINED DEFINER=`autho`@`%` SQL SECURITY DEFINER VIEW `v_authing` AS select `u`.`USER_NAME` AS `USER_NAME`,`t`.`USER_ID` AS `USER_ID`,`c`.`SYS_DESC` AS `SYS_DESC`,`t`.`OS_HOSTNAME` AS `OS_HOSTNAME`,`t`.`CLIENT_IP` AS `client_ip`,`t`.`OS_MAC` AS `OS_MAC`,`t`.`JAR_MD5` AS `JAR_MD5` from ((`t_req_auth_log` `t` left join `t_user_conf` `u` on((`t`.`USER_ID` = `u`.`USER_ID`))) left join `t_sys_conf` `c` on((`t`.`SYS_ID` = `c`.`SYS_ID`))) order by `t`.`USER_ID` */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
