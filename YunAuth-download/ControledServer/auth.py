#!/usr/bin/python
#encoding=gbk


import MySQLdb
import os
import time

def execCmd(cmd): 
	r = os.popen(cmd)
	text = r.readlines()
	#text=os.open(cmd).readlines()
	r.close()
	return text;

def logger(loglevel,logmsg):
	logtime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
	flog.write("["+logtime+"]["+loglevel+"]["+logmsg+"]\n")
	print "["+logtime+"]["+loglevel+"]["+logmsg+"]"
	return;

def exit_py(exitcode):
#	conn.commit()
#	conn.close()
	logger("info","exitcode="+str(exitcode))
	flog.close()
	quit(exitcode)
	return;

#------------main area-------------------
conn=MySQLdb.connect(
	host='XXX.XXX.XXX.XXX',
	port=33061,
	user='XX',
	passwd='XXXX',
	db='myauth'
	)

basedir=os.getenv('HOME')
local_ip=os.getenv('AUTH_SERVER_IP')
logpath=basedir+"/log"
logfile=logpath+"/auth.log"
os.system("mkdir -p "+logpath)
flog=open(logfile,"a+")

#print local_ip
if (local_ip==None):
	logger("fatal","env variant AUTH_SERVER_IP is not set")
	exit_py(91)

cur=conn.cursor()

##---
##local_ip="99.99.99.99"
#---

logger("info","-----------------------"+local_ip+"---------------------------------------")
#---����������Ȩ�ļ�¼
logger("info","begin to deal with applying auth records...")
AuthCUR=cur.execute("SELECT  a.client_ip,a.sys_id,b.sys_port,a.req_sn,a.user_id FROM t_req_auth_log a  , t_sys_conf  b where  a.sys_id=b.sys_id and a.process_flag='0' and a.req_type='1' and b.sys_ip='"+local_ip+"'")
#aa=cur.execute("select  * from t_user_conf")
logger("info","applying Auth record num is "+str(AuthCUR))

info=cur.fetchmany(AuthCUR)
chain=""
client_ip=""
sys_port=""
req_sn=""
user_id=""
for ii in info:
	user_id=ii[4]
	req_sn=ii[3]
	sys_port=ii[2]
	chain=ii[1]
	client_ip=ii[0]
	logger("info","*** insert into "+chain+" with "+client_ip+" which req_sn is "+str(req_sn))
	cmd="iptables -L "+chain+" -n --line-numbers"
	logger("info",cmd)
	ret=os.system(cmd)
	logger("info","ret="+str(ret))
	if ret!=0:
		#--���û�ж�Ӧ��CHAIN����ô�����µ�chain
		cmd="iptables -N "+chain
		logger("info","create a new chain named:["+chain+"]->"+cmd)
		sret=os.system(cmd)
		if sret!=0:
			logger("fatal","create chain "+chain+" failed.")
			exit_py(90)
		else:
			#--����CHAIN�󣬳�ʼ�����ϸ����
    		
			cmd="iptables -I "+chain+" -p tcp --dport "+str(sys_port)+" -j DROP "
			logger("info","Adding a initial rule to new chain ["+chain+"]")
			logger("info",cmd)
			sret=os.system(cmd)
			if sret!=0:
				logger("fatal","Add a initial rule to new chain["+chain+"] failed!")
				exit_py(90)
    		
			cmd="iptables -I "+chain+" -s "+client_ip+" -p tcp --dport "+str(sys_port)+" -j ACCEPT"
			logger("info","Inserting a new rule to chain ["+chain+"]")
			logger("info","["+user_id+"]"+cmd)
			sret=os.system(cmd)
			if sret!=0:
				logger("fatal","Inserting a new rule to chain["+chain+"] failed!")
				exit_py(90)
    		
	else:
		#--����Ѿ����ڸ�CHAIN����ô���������Ȩ����tables
		cmd="iptables -I "+chain+" -s "+client_ip+" -p tcp --dport "+str(sys_port)+" -j ACCEPT"
		logger("info","Inserting a new rule to chain ["+chain+"]")
		logger("info","["+user_id+"]"+cmd)
		sret=os.system(cmd)
		if sret!=0:
			logger("fatal","Inserting a new rule to chain["+chain+"] failed!")
			exit_py(90)
##
	try:		
		upCUR=cur.execute("update t_req_auth_log set process_flag='1' where req_sn="+str(req_sn))
	except:
		conn.rollback()
		logger("error","change req_sn {"+str(req_sn)+"} to Authed failed.")
		exit_py(90)
	else:
		logger("info","change req_sn {"+str(req_sn)+"} to Authed success.")
		conn.commit()

logger("info","end of to deal with applying auth records...")


#--��ʼ�������� ����Ȩ�ļ�¼
logger("info","begin to deal with applying un-auth records...")

unAuthCUR=cur.execute("SELECT  a.client_ip,a.sys_id,b.sys_port,a.req_sn,a.user_id FROM t_req_auth_log a  , t_sys_conf  b where  a.sys_id=b.sys_id and a.process_flag='0' and a.req_type='0' and b.sys_ip='"+local_ip+"'")
logger("info","applying unAuth record num is "+str(unAuthCUR))
info=cur.fetchmany(unAuthCUR)
chain=""
client_ip=""
sys_port=""
req_sn=""
user_id=""
for ii in info:
	user_id=ii[4]
	req_sn=ii[3]
	sys_port=ii[2]
	chain=ii[1]
	client_ip=ii[0]
	logger("info","*** delete from "+chain+" with "+user_id+":"+client_ip+" which req_sn is "+str(req_sn))
	#cmd="iptables -L "+chain+" -n --line-numbers|grep "+client_ip+"|awk '{print \"iptables -D "+chain+" \"$1}'"
	cmd="iptables -L "+chain+" -n --line-numbers|grep "+client_ip+"|awk '{print $1}'"
	logger("info",cmd)
	cresult=execCmd(cmd)
	
	idx=0
	for jj in cresult:
		rline=int(jj[0])-idx
		cmd="iptables -D "+chain+" "+str(rline)
		logger("info","["+user_id+"]delete from "+chain +" :"+cmd)
		sret=os.system(cmd)
		if sret!=0:
			logger("error","delete from chain:"+chain+" :"+cmd+" failed!")
			exit_py(90)
		else:
			idx=idx+1
	try:
		upCUR=cur.execute("update t_req_auth_log set process_flag='1' where req_sn="+str(req_sn))
		upCUR=cur.execute("insert into t_req_auth_log_his (REQ_SN,REQ_TIME,CLIENT_IP,CLIENT_PORT,user_id,sys_id,req_co_time,req_type,process_flag,OS_TYPE,OS_USER,OS_HOSTNAME,OS_MAC,JAR_MD5) select  * from t_req_auth_log where req_sn="+str(req_sn))
		upCUR=cur.execute("delete from t_req_auth_log where req_sn="+str(req_sn))
	except:
		conn.rollback()
		logger("info","change req_sn {"+str(req_sn)+"} to un-Authed failed!")
		exit_py(90)
	else:
		conn.commit()
		logger("info","change req_sn {"+str(req_sn)+"} to un-Authed success.")

logger("info","end of to deal with applying un-auth records...")
#	print ret


#--��ʼ�����ʵ����Ȩ�������¼
#���Ѿ����ڣ���ô����Ȩ�޻��գ������Թ�
#��ʹ��IP���п��ƣ��ʽ����ֶ�����ͬһIP�����룬������Ϊ����ͬIP����ͬһ��Ӧ���ж��������Ȩ(���տͻ���IP��ϵͳID���з���)����ô��δ���ڵ�����Ϊ���Ƚ�����Ȩ�ӳ�
logger("info","begin to revoke authed application records...")
logger("info","local_ip="+local_ip)

#-���տͻ���IP��ϵͳID���з��鴦��
strSQL="SELECT  A.client_ip,B.SYS_ID ,COUNT(*) FROM t_req_auth_log a, t_sys_conf  b  " + \
	"WHERE a.sys_id=b.sys_id  AND a.PROCESS_FLAG='1' AND a.req_type='1' AND b.sys_ip='"+local_ip+"'  GROUP BY A.CLIENT_IP,B.SYS_ID"

GrpCUR=cur.execute(strSQL)
oinfo=cur.fetchmany(GrpCUR)
GClient_ip=""
GSys_id=""
for ii in oinfo:
	GClient_ip=ii[0]
	GSys_id=ii[1]
#-��ѯ��Ӧ����ļ�¼	
	strSQL_inner="SELECT  a.client_ip,a.sys_id,b.sys_port,a.req_sn,a.USER_ID ,A.REQ_TIME,A.REQ_CO_TIME,"+ \
	" CASE WHEN DATE_ADD(a.REQ_TIME,INTERVAL  a.REQ_CO_TIME MINUTE)<CURRENT_TIMESTAMP  THEN '1' "+ \
	" ELSE '0' END DEL_FLAG "+ \
	" FROM t_req_auth_log a , t_sys_conf  b "+ \
	" WHERE a.sys_id=b.sys_id "+ \
	" AND a.process_flag='1' AND a.req_type='1' "+ \
	" AND b.sys_ip='"+local_ip+"'"+ \
	" AND a.client_ip='"+GClient_ip+"' AND a.sys_id='"+GSys_id+"' ORDER BY DEL_FLAG ASC"
	iCUR=cur.execute(strSQL_inner)
	logger("info","Client_ip "+GClient_ip+" on sys_id "+GSys_id+" Authed record num is "+str(iCUR))
	iinfo=cur.fetchmany(iCUR)

#GDelChainFlag =0 ,��ʾΪ��chain��Ӧ�ĸ�ip��Ӧ�Ĺ���ɾ��������Ҫɾ��	
	GDelChainFlag="1"
#query list�е�del_flag��=0����ôδ����;��Ϊ1����ô�Ѿ�����.	
	delChainFlag="1"
	chain=""
	client_ip=""
	sys_port=""
	req_sn=""
	user_id=""
	for jj in iinfo:
		delChainFlag=jj[7]
		user_id=jj[4]
		req_sn=jj[3]
		sys_port=jj[2]
		chain=jj[1]
		client_ip=jj[0]
		if delChainFlag=='0':
			#��δ���ڣ���ô����һ�±������ȫ��ɾ����־����������һ����¼����
			GDelChainFlag="0"
			continue
		else:
			#��ȫ�ֱ�־Ϊ��ɾ������ô�������ݿ��е�Ȩ�ޣ�����ɾ������ǽ���򣬷������߶�����
			if GDelChainFlag=='0':
				try:
					upCUR=cur.execute("update t_req_auth_log set process_flag='2' where req_sn="+str(req_sn))
					upCUR=cur.execute("insert into t_req_auth_log_his (REQ_SN,REQ_TIME,CLIENT_IP,CLIENT_PORT,user_id,sys_id,req_co_time,req_type,process_flag,OS_TYPE,OS_USER,OS_HOSTNAME,OS_MAC,JAR_MD5) select  * from t_req_auth_log where req_sn="+str(req_sn))
					upCUR=cur.execute("delete from t_req_auth_log where req_sn="+str(req_sn))
				except:
					conn.rollback()
					logger("info","revoke req_sn {"+str(req_sn)+"} in database failed!")
					exit_py(90)
				else:
					conn.commit()
					logger("info","revoke req_sn {"+str(req_sn)+"} in database success.")
				#--����ɾ������ǽ��������£����ݿ���ս���	
			else:
				#-�������ݿ�ͷ���ǽ����
				logger("info","*** delete from "+chain+" with "+client_ip+" which req_sn is "+str(req_sn))
				cmd="iptables -L "+chain+" -n --line-numbers|grep "+client_ip+"|awk '{print $1}'"
				logger("info",cmd)
				cresult=execCmd(cmd)
				
				idx=0
				for mm in cresult:
					rline=int(mm[0])-idx
					cmd="iptables -D "+chain+" "+str(rline)
					logger("info","["+user_id+"]delete from "+chain +" :"+cmd)
					sret=os.system(cmd)
					if sret!=0:
						logger("error","delete from chain:"+chain+" :"+cmd+" failed!")
						exit_py(90)
					else:
						idx=idx+1
				
				try:
					#-��ǽ���Ϊ��Ȩ���գ���ת�Ƶ���ʷ��
					upCUR=cur.execute("update t_req_auth_log set process_flag='2' where req_sn="+str(req_sn))
					upCUR=cur.execute("insert into t_req_auth_log_his (REQ_SN,REQ_TIME,CLIENT_IP,CLIENT_PORT,user_id,sys_id,req_co_time,req_type,process_flag,OS_TYPE,OS_USER,OS_HOSTNAME,OS_MAC,JAR_MD5) select  * from t_req_auth_log where req_sn="+str(req_sn))
					upCUR=cur.execute("delete from t_req_auth_log where req_sn="+str(req_sn))
				except:
					conn.rollback()
					logger("error","revoke req_sn {"+str(req_sn)+"} failed!")
					exit_py(90)
				else:
					conn.commit()
					logger("info","revoke req_sn {"+str(req_sn)+"} success.")
				
	
	



####strSQL="SELECT  a.client_ip,a.sys_id,b.sys_port,a.req_sn,a.USER_ID ,A.REQ_TIME,A.REQ_CO_TIME FROM t_req_auth_log a , t_sys_conf  b"+ \
####	" WHERE a.sys_id=b.sys_id " \
####	" AND a.process_flag='1' AND a.req_type='1' AND DATE_ADD(a.REQ_TIME,INTERVAL  a.REQ_CO_TIME MINUTE)<CURRENT_TIMESTAMP and b.sys_ip='"+local_ip+"'"
####AuthedCUR=cur.execute(strSQL)
####logger("info","Authed apply record num is "+str(AuthedCUR))
####info=cur.fetchmany(AuthedCUR)
####chain=""
####client_ip=""
####sys_port=""
####req_sn=""
####user_id=""
####for ii in info:
####	user_id=ii[4]
####	req_sn=ii[3]
####	sys_port=ii[2]
####	chain=ii[1]
####	client_ip=ii[0]
####	logger("info","*** delete from "+chain+" with "+client_ip+" which req_sn is "+str(req_sn))
####	cmd="iptables -L "+chain+" -n --line-numbers|grep "+client_ip+"|awk '{print $1}'"
####	logger("info",cmd)
####	cresult=execCmd(cmd)
####	
####	idx=0
####	for jj in cresult:
####		rline=int(jj[0])-idx
####		cmd="iptables -D "+chain+" "+str(rline)
####		logger("info","["+user_id+"]delete from "+chain +" :"+cmd)
####		sret=os.system(cmd)
####		if sret!=0:
####			logger("error","delete from chain:"+chain+" :"+cmd+" failed!")
####			exit_py(90)
####		else:
####			idx=idx+1
####	try:
####		#-��ǽ���Ϊ��Ȩ���գ���ת�Ƶ���ʷ��
####		upCUR=cur.execute("update t_req_auth_log set process_flag='2' where req_sn="+str(req_sn))
####		upCUR=cur.execute("insert into t_req_auth_log_his (REQ_SN,REQ_TIME,CLIENT_IP,CLIENT_PORT,user_id,sys_id,req_co_time,req_type,process_flag) select  * from t_req_auth_log where req_sn="+str(req_sn))
####		upCUR=cur.execute("delete from t_req_auth_log where req_sn="+str(req_sn))
####	except:
####		conn.rollback()
####		logger("info","revoke req_sn {"+str(req_sn)+"} failed!")
####		exit_py(90)
####	else:
####		conn.commit()
####		logger("info","revoke req_sn {"+str(req_sn)+"} success.")

logger("info","end of to revoke authed records...")

#cur.close()
#conn.commit()
#conn.close()

exit_py(0)
