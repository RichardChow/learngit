#!/usr/bin/env python
# -*- coding: utf-8-*- #


"""
Name:
    ssh_cli 

Description:
    
Copyright (c) 2015-2020 ecitele, Inc.

History:
    2017-3-1    Wei.Hu    Create 
"""
import sys
import re

import datetime
import shutil
#import logging
import Tkinter
import SSHLibrary
import time
#import string
import os
import glob
from robot.libraries.String import String
from robot.api import logger
from robot.libraries.Collections import Collections 
from robot.libraries.BuiltIn import BuiltIn
ROBOT_LIBRARY_SCOPE = 'GLOBAL'
ROBOT_LIBRARY_VERSION = '1.0'
import DebugLibrary
import traceback


sys.path.append('C:/NPTI_CLI/Lib')

def lib_robot_var():
    global DICT_dev
    DICT_dev = {}
    global TEQ_FLAG,LOG_FLAG,DELETE_FLAG,SPT_FORCE
    TEQ_FLAG=BuiltIn().get_variable_value("${teq_flag}")
    LOG_FLAG=BuiltIn().get_variable_value("${log_flag}")
    DELETE_FLAG=BuiltIn().get_variable_value("${delete_flag}")
    SPT_FORCE=BuiltIn().get_variable_value("${spt_force}")
    print('SPT_FORCE:',SPT_FORCE)
    DICT_dev=BuiltIn().get_variable_value("&{DICT_INFO}")
    global robot_cli
    robot_cli=DebugLibrary.DebugLibrary()
    
def lib_qtp_var():
    global DICT_dev
    DICT_dev = {}
    global TEQ_FLAG,LOG_FLAG,DELETE_FLAG,SPT_FORCE
    TEQ_FLAG=''
    LOG_FLAG=''
    DELETE_FLAG=''
    SPT_FORCE=''
    
def cli_export_version(txt_name="", tar_path=""):
    '''des:get version and write in version.txt   \n
    txt_name: 7.0.txt       \n
    tar_path: d:/version/npti_cli   \n
    '''
    try:
        ver_pat = re.compile('V\d\.\d\.\d{3}')
        cmd_rst = cli_cmd("run show version")
        ver_rst = ver_pat.findall(cmd_rst)
        if len(ver_rst) == 0 :
            rsf=1
            rst='Can not get version.'
            #logger.error()                
            raise CmdError('%s ->\n%s' %(cmd_rst,rst))    
        elif len(ver_rst) > 1 :
            if ver_rst[0] == ver_rst[1] :
                ver_info = ver_rst[0]
            else :
                rsf = 1
                rst='Version inconformity %s <> %s' % (ver_rst[0], ver_rst[1]) 
                #logger.error()                
                raise CmdError('%s ->\n%s' %(cmd_rst,rst))
        else :
            ver_info = ver_rst[0]
        # write version info into txt.
        if txt_name == "" :
            return ver_info
        else :
            txt = txt_name + '.txt'
            file_path = os.path.join(tar_path, txt)
            logger.info('Ready save file path: %s .' % file_path)
            with open(file_path, 'w') as d:
                d.write(ver_info)
            logger.info('Save file success!')
    except (CmdError,FatalError):
        raise
    except Exception,ex_msg:
        rsf=1
        raise CmdError(ex_msg)
    
def lib_get_var():
    global TEQ_FLAG,LOG_FLAG,DELETE_FLAG,SPT_FORCE,PAUSE_ON_ERR
    global DICT_TOPO     # for all device in topo file
    global CLS_DEBUG     # for debug library
    TEQ_FLAG=''
    LOG_FLAG=''
    DELETE_FLAG=''
    SPT_FORCE=''
    PAUSE_ON_ERR=''
    DICT_TOPO={}
    if LOAD_MODE=='robot':

        CLS_DEBUG=DebugLibrary.DebugLibrary()
        PAUSE_ON_ERR=BuiltIn().get_variable_value("${pause_on_error}")
        TEQ_FLAG=BuiltIn().get_variable_value("${teq_flag}")
        LOG_FLAG=BuiltIn().get_variable_value("${log_flag}")
        DELETE_FLAG=BuiltIn().get_variable_value("${delete_flag}")
        SPT_FORCE=BuiltIn().get_variable_value("${spt_force}")
        DICT_TOPO=BuiltIn().get_variable_value("&{DICT_TOPO}")
    else:
        #LOAD_MODE='qtp' 
        #CLS_DEBUG=DebugLibrary.DebugLibrary()
        #PAUSE_ON_ERR='false'
        TEQ_FLAG='true'
        pass
  

def cli_check_cmd(cmd,pattern,loop=10,interval=10,flag='yes',error_stop='yes'):
    '''des:get cmd's result and match with regrex   \n
    cmd:run show chassis status|grep '\<ts1\>'  \n
    pattern: regrex, \\bts1\\b.*\\bUp\\b    \n
    loop:wait 60s and if failed will retry  \n
    flag:if flag='yes' and match ok,return pass->\n
    error_stop:
    '''

    i=1
    try:
        while i<=int(loop):
            #a='a'+1
            logger.info('The %s times to check ....' %i,also_console=True)
            i=i+1
            cmd_rst=cli_cmd(cmd)
            list_rst=re.findall(pattern,cmd_rst)
            if len(list_rst)==0:
                if flag=='yes':
                    rsf=1
                    rst='<b>Can NOT find</b> %s ,but flag is %s' % ( pattern,flag)
                    logger.info(rst,True)
                    #return rsf
                else:
                    rsf=0
                    rst='can not find %s and flag is %s' % ( pattern,flag)
                    logger.info(rst)
                    #return list_rst
            else:
                if flag=='yes':
                    rsf=0
                    rst='can find %s and flag is %s' % ( pattern,flag)
                    logger.info(rst) 
                    #return list_rst
                else:
                    rsf=1
                    rst='<b>Can find</b> %s ,but flag is %s' % ( pattern,flag)
                    logger.info(rst,True)
                    #return rsf
            if rsf==0:
                break
            else:
                if i<=int(loop):
                    logger.console('Waiting for %s secend,Try again...' % interval)
                    time.sleep(int(interval))
    except (CmdError,FatalError):
        rsf=1
        raise
    except Exception as e:
        rsf=1
        raise CmdError(repr(e)) 
        
    else:
        if rsf==1:
            #logger.error(rst,True)
            if error_stop=='yes' :
                raise CmdError(rst) 
            else:
                return rst
        else:
            return list_rst

def cli_get_regrex(cmd_rst,pattern,*groups):
    '''des:match with regrex    \n
    '''
    
    if len(groups)==0:
        return re.findall(pattern,cmd_rst)
    else:
        groups = [int(g) for g in groups]
        return [m.group(*groups) for m in re.finditer(pattern,cmd_rst)]
  

def _cli_find(pattern,str,flag='yes'):

    #pattern=re.escape(pattern)
    #print(pattern)
    res = re.findall(pattern, str)
    return res
    
def _cli_finditer(pattern,str,*groups):
    #groups=int(group)
    #res = re.finditer(pattern, str)
    groups = [int(g) for g in groups]
    return [m.group(*groups) for m in re.finditer(pattern,str)]
    
def _cli_search(pattern,str):
    #should return 0 ,when (a|b)
    #pattern=re.escape(pattern)
    #print(pattern)
    res = re.search(pattern, str)
    if res is None:
        
        print('search:None')
        return 1
    else:
        
        match = res.group(0)
        groups = res.groups()
        if groups:
            #[match] + list(groups)
            #[u'System Operational Status : Up\r', u'System', u'Up']
            print(res.span())
            print('search1:', match)
            print('search1:', groups)
        else:
            span=res.span()
            print('search2:%s' % match)
            print('search2:' , span)
        return 0


class myError(Exception):
    num_count = 0 
    #logger.info('Load_Mode:%s,PAUSE_ON_ERR:%s ' % (LOAD_MODE,PAUSE_ON_ERR),also_console=True)
    def __init__(self, message=''):
        self.__class__.num_count += 1 
        #logger.info('\n init ===' + str(self.__class__.num_count) +'===',also_console=True)
        Exception.__init__(self, message)
        trace_str=traceback.format_exc()
        if LOAD_MODE=='robot' :
            if self.__class__.num_count==1 :
               logger.error(message)
            if trace_str.find('Traceback')>=0 and trace_str.find('cmd.py')<0 :
                logger.debug(trace_str)
            if PAUSE_ON_ERR=='true'  and self.__class__.num_count==1:
                CLS_DEBUG.debug()
        else:
            if trace_str.find('Traceback')>=0 and trace_str.find('cmd.py')<0 :
                logger.console(trace_str )
            else:
                #logger.console('qtp ' + message)
                pass
    def __del__(self):  
        self.__class__.num_count -= 1
        #logger.console('\n del===' + str(self.__class__.num_count) +'===')
        pass

class CmdError(myError):
    pass

class TeqError(myError):
    pass

class CheckError(myError):
    pass
    
class FatalError(myError):
    ROBOT_EXIT_ON_FAILURE = True
    
    
def raise1(str='cmd'):
    try:
        if str=='cmd':
            raise CmdError('abc')
        if str=='fatal':
            raise FatalError('abc')
        if str=='cli':
            raise myError('abc')
        if str=='exp':
            raise Exception('abc','aa')
        if str=='1':
            a=1/0
        if str=='2':
            a=b
        #a=1+'a'
        cli_cmd(str)
        print('end def')
        #a=1+'a'
    # except NameError as e:
        # raise myError('NameError_%s' % e)
    except FatalError as e:
        print('Fatal raise1')
        raise 
    except CmdError as e:
        print('CmdError raise1')
        raise #CmdError(e)
    except Exception , e:
        print('Exception raise1')
        raise CmdError('raise1_%s' % e)
def raise2(str):
    try:
        raise1(str)
        b=1+'b'
    except FatalError as e:
        print('fatal raise2')
        raise
    except CmdError as e:
        print('CmdError raise2')
        raise
    except Exception as e:
        raise CmdError('raise2_%s' % repr(e)) 
        

def cli_check_alarm(alarms, cmd='run show ne alarms', flag=0, Fatal=0):
    '''des:check alarms   \n
    alarms: Card-Ctrl-Fail|Cfg-Sync-Failed   \n
    cmd=run show ne alarms/run show ne alarms | grep system   \n
    flag=0/1 If flag=0 and not match, return pass, Else flag=1 and match, return pass, Else return fail.   \n
    Fatal=0/1 If Fatal=1 and check_alarm fail, stop AT test. Else continue test.   \n
    '''
    try:
        cmd_rst = cli_cmd(cmd)
        fpat = re.compile(r'%s' % alarms, re.I)
        get_fault = fpat.findall(cmd_rst)
        if len(get_fault) > 0:
            if int(flag)==0:
                fault_state = 1
            else:
                fault_state = 0
        else :
            if int(flag)==0:
                fault_state = 0
            else:
                fault_state = 1
        if fault_state==1 and int(Fatal)==1:
            rsf='Fatal Fail. Alarms: %s <> Flag: %s. AT stop.' % (get_fault, flag)
            rst=1
            #logger.error('check_alarm : %s' % rsf)
            raise FatalError('check_alarm : %s' % rsf)
        elif fault_state==1 and int(Fatal)==0:
            rsf='Fail. Alarms: %s <> Flag: %s. Fail.' % (get_fault, flag)
            rst=1
            logger.error('check_alarm : %s' % rsf)
        else:
            rsf='Pass. Alarms: %s == Flag: %s. Pass.' % (get_fault, flag)
            rst=0
            logger.info('check_alarm : %s' % rsf)
    except (CmdError,FatalError):
        raise
    except Exception,ex_msg:
        raise CmdError(ex_msg) 


def _cli_log(msg):
    try:
        logger.log('log:%s' %msg,True,True)
        logger.log('log:%s' %msg,False,True)
        logger.log('log:%s' %msg,True,True)
        logger.log('log:%s' %msg,True,True)
    except Exception,except_msg:
        rst=1
        rs_msg=except_msg
    else:
        #rst=0
        pass
    finally:
        return cli_report(rst,rs_msg)

def _rst_add(status,fun_msg):
    LIST_FUN.append(status)
    LIFT_FUN.append(fun_msg)

def _rst_update():
    pass
def _old_login():
    global ssh_lib
    global GLB_PROMPT_REG
    hostid=ssh_lib.open_connection(ip,alias=ip,prompt=':~#')
    print('open:%d' %hostid)
    ssh_lib.set_client_configuration(width=100)
    host_info=ssh_lib.get_connection()
    print('host_conf:%s' %host_info)
    
    output=ssh_lib.login('root','root')
    print('login:%s' %output)
    
    ssh_lib.write("ls /sdboot/up")
    output=ssh_lib.read_until_prompt()
    print('ls:%s' %output)
    
    ssh_lib.write("lsh")
    output=ssh_lib.read_until_regexp('.*@.*> $')
    print('lsh:%s' %output)
    ssh_lib._log(output,'INFO')
    if mode=='config':
        ssh_lib.write("config")
        output=ssh_lib.read_until_regexp('.*@.*# $')
        print('config:%s' %output)
        ssh_lib._log(output,'INFO')

def _rst_isPass():
    cnt=LIST_FUN.count(1)
    if cnt>0:
        return False
    else:
        return True

def _rst_report(status,fun_msg):
    
    rst_add(status,fun_msg)
    
    if status==-1:
        str_detail='Done:%s' % fun_msg
    elif status==0:
        str_detail='Passed:%s' % fun_msg
    elif status==1:
        str_detail='Error:%s' % fun_msg
    elif status==2:
        str_detail='Failed:%s' % fun_msg
    elif status==3:
        str_detail='Warning:%s' % fun_msg
    else:
        str_detail='None:%s' % fun_msg
    pass
    if Robot=='True':
        if cont_on_error=='False':
            raise Exception(fun_msg)
        else:
            return (status,fun_msg)
    else:
        #wirte reg??
        return (status,fun_msg)
        






def cli_close(userinfo=None):
    '''des:close ssh session for ne   \n
    userinfo=user + "@" + ip   \n
    user@ip=admin@200.200.18.101
    '''
    print('DICT_HOST:%s ' % DICT_HOST)
    if userinfo==None:
        ip_keys=ssh_lib.get_connection().alias
        if ip_keys == None :
            logger.info('no connection exist')
        else:
            Connectinfo=DICT_HOST.get(ip_keys)
            if Connectinfo == None :
                logger.info('no connection exist')
            else:
                Collections().pop_from_dictionary(DICT_HOST,ip_keys)
                ssh_lib.close_connection()
                logger.info('cli_close:%s ' % Connectinfo)            
                pass
    elif userinfo=='all':
        if DICT_HOST==None:
            logger.info('no connection exist')
        else:
            for key in Collections().get_dictionary_keys(DICT_HOST):
                Collections().pop_from_dictionary(DICT_HOST,key)
                logger.info('cli_close:%s ' % key)
            ssh_lib.close_all_connections()
            pass
    else:
        ip_keys=ssh_lib.get_connection(userinfo).alias
        if ip_keys == None :
            logger.info('no connection exist')
        else:
            Connectinfo=DICT_HOST.get(ip_keys)                
            if Connectinfo == None :
                logger.info('Connectinfo:no connection exist')
            else:
                Collections().pop_from_dictionary(DICT_HOST,ip_keys)
                ssh_lib.close_connection()
                logger.info('cli_close:%s ' % ip_keys)     
                pass
    logger.info('DICT_HOST:%s ' % DICT_HOST)
def cli_switch_mode(mode):
    '''des:switch cli mode    \n
    mode:config/oper/shell    \n
    '''
    output=""
    ip_keys=ssh_lib.get_connection().alias
    Connectinfo=DICT_HOST.get(ip_keys)
    logger.info(DICT_HOST) 
    src_mode=Collections().get_from_dictionary(Connectinfo,"mode")
    user=Collections().get_from_dictionary(Connectinfo,"user")
    logger.info(user) 
    logger.info(mode) 
    if user =="root":
        if src_mode=="shell":
            if mode == "config":
                output=cli_cmd('lsh')
                #logger.info("output:",output) 
                output=cli_cmd('config')
            elif mode == "oper":
                output=cli_cmd('lsh')
            else:
                pass
        elif src_mode =='oper':
            if mode == 'config':
                output=cli_cmd('config')
            elif mode == 'shell':
                output=cli_cmd('exit')
            else:
                pass
        elif src_mode =='config':
            if mode == "oper":
                output=cli_cmd('exit')
            elif mode == "shell":
                output=cli_cmd('exit')
                output=cli_cmd('exit')
            else:
                pass
        else:
            pass
    else:
        if src_mode=="shell":
            if mode == "config":
                output=cli_cmd('exit')
                output=cli_cmd('config')
            elif mode == "oper":
                output=cli_cmd('exit')
            else:
                pass
        elif src_mode =='oper':
            if mode == 'config':
                output=cli_cmd('config')
            elif mode == 'shell':
                output=cli_cmd('start shell')
            else:
                pass
        elif src_mode =='config':
            if mode == "oper":
                output=cli_cmd('exit')
            elif mode == "shell":
                output=cli_cmd('exit')
                output=cli_cmd('start shell')
            else:
                pass
    Collections().set_to_dictionary(Connectinfo,"mode",mode)
    

def cli_login(ip,user='admin',passwd='admin1',retry='2',mode='config'):
    '''des:login ne with ip@user    \n
    ip:   \n
    user=root/admin   \n
    passwd=root/admin1      \n
    loop=2:wait 60s and loop times if down   \n
    mode=config/oper/shell     \n
    '''
    i=1
    rsf=1
    Connectinfo={}
    # global ssh_lib
    # global GLB_PROMPT_REG
    # global DICT_HOST
    #DICT_HOST={}
    keys=user + "@" + ip
    try:
        Connectinfo=DICT_HOST.get(keys)
        print("Connectinfo:",Connectinfo)
        if Connectinfo == None :
            if user == "root" :
                prompt = "~#"
            else:
                prompt = ">"
            index=ssh_lib.open_connection(ip,alias=keys,prompt=prompt)
            #Collections().set_to_dictionary(DICT_HOST,keys,values)
            ssh_lib.set_client_configuration(width=100,timeout=11)
        else:
            print('cli_login:')
            index=Collections().get_from_dictionary(Connectinfo,"index")
            logger.info('has login')
            logger.info(Connectinfo)
            ssh_lib.switch_connection(index)
            cli_switch_mode(mode)
            return 0
    except (CmdError,FatalError):
        rsf=1
        raise    
    except Exception,ex_msg:
        rsf=1
        raise CmdError(ex_msg)
    else:
        while i<=int(retry):
            try:
                logger.info('\nThe %s times login to ....' %i,also_console=True)
                i=i+1
                #open and login
                ssh_lib.login(user,passwd)
                if user == "root":
                    if mode=='config':
                        output=cli_cmd('lsh')
                        output=cli_cmd('config')
                    elif mode=='oper':
                        output=cli_cmd('lsh')
                    else:
                        pass
                else:
                    if mode=='config':
                        output=cli_cmd('config')
                        cli_cmd('run set cli idle-timeout 99999')
                    elif mode=='shell':
                        output=cli_cmd('start shell')
                        cli_cmd('set cli idle-timeout 99999')
                    else:
                        pass
            except FatalError, ex_msg:
                logger.info(ex_msg)
                time.sleep(300)
                rsf=0
                break
            except CmdError, ex_msg:
                logger.info(ex_msg)
                time.sleep(300)
                rsf=0
                break
            except Exception,ex_msg:
                logger.info(ex_msg)
                if i<=int(retry):
                    logger.info('Waiting for 60s,Try again login...',also_console=True)
                    time.sleep(60)
                else:
                    raise CmdError(ex_msg)
            else:
                rsf=0
                break

    if rsf==1 :
        raise
    else:
        #logger.info('ok')
        values={"ip":ip,"mode":mode,"index":index,"user":user}
        Collections().set_to_dictionary(DICT_HOST,keys,values)
        logger.info('cli_login:index:%s' % index)

        return 0


def cli_npt_login(ip,user='root',passwd='root',retry='2',mode='oper'):
    '''des:login ne with ip@user    \n
    ip:   \n
    user=root   \n
    passwd=root     \n
    loop=2:wait 60s and loop times if down   \n
    mode=config/oper/shell     \n
    '''
    i=1
    rsf=1
    Connectinfo={}
    # global ssh_lib
    # global GLB_PROMPT_REG
    # global DICT_HOST
    #DICT_HOST={}
    keys=user + ">" + ip
    try:
        Connectinfo=DICT_HOST.get(keys)
        print("Connectinfo:",Connectinfo)
        if Connectinfo == None :
            if user == "root":
                prompt = ">"
            index=ssh_lib.open_connection(ip,alias=keys,prompt=prompt)
            #Collections().set_to_dictionary(DICT_HOST,keys,values)
            ssh_lib.set_client_configuration(width=100,timeout=11)
        else:
            print('cli_npt_login:')
            index=Collections().get_from_dictionary(Connectinfo,"index")
            print(index)
            logger.info('has login')
            logger.console('has login')
            logger.info(Connectinfo)
            logger.console(Connectinfo)
            ssh_lib.switch_connection(index)
            cli_npt_switch_mode(mode)
            return 0
    except Exception,msg:
        rsf=1
        raise
    else:
        while i<=int(retry):
            try:
                logger.info('\nThe %s times login to ....' %i,also_console=True)
                i=i+1
                #open and login
                ssh_lib.login(user,passwd)
                if user == "root":
                    if mode=='config':
                        output=cli_cmd('en')
                    elif mode=='shell':
                        output=cli_cmd('en')
                        output=cli_cmd('sw sh')
                    else:
                        pass
            except CmdError, msg:
                logger.info(msg)
                time.sleep(300)
                rsf=0
                break
            except Exception,msg:
                logger.info(msg)
                if i<=int(retry):
                    logger.info('Waiting for 60s,Try again login...',also_console=True)
                    time.sleep(60)
            else:
                rsf=0
                break

    if rsf==1 :
        raise Exception(msg)
        #raise RuntimeError(msg)
    else:
        logger.info('ok')
        values={"ip":ip,"mode":mode,"index":index,"user":user}
        Collections().set_to_dictionary(DICT_HOST,keys,values)
        print('cli_npt_login:index:', index)
        return 0


def cli_npt_ftp_version(dir_local,netype='NPT1200'):
    '''des:ftp version from dir_local to /sdboot/up of NE   \n
    dir_local:   D:/Version/npt_ems  \n
    netype=NPT1200/NPT1050/NPT1010/NPT1020   \n
    nemode=1+1/1+0/2+0  \n
    '''
    try:
        cli_npt_switch_mode("shell")
        file_remote='/sdboot/up/' + netype + '_Emb.bin'
        print(netype)
        file_local=netype + '_Emb_' + '[0-9][0-9]*.bin'
        f_file=glob.glob(dir_local + '/' + file_local)
        print(f_file)
        le=len(f_file)
        if len(f_file)!=1:
            raise AssertionError('file number is %d:%s' % (len(f_file),f_file) )
        size_local=os.path.getsize(f_file[0])
        print(size_local)
        
        #delete .bin.old file and rename .bin file to .bin.old
        print(cli_cmd('pwd'))
        cli_cmd('cd "/sdboot/up"')
        print(cli_cmd('ls "/sdboot/up"'))
        cli_cmd('rm ' + '"' + netype + '_Emb.bin.old' + '"')
        cli_cmd('rename ' + '"' + netype + '_Emb.bin' + '"' + ',' + '"' + netype + '_Emb.bin.old' + '"')
        #time.sleep(3)
        
        #put version
        rst_debug=cli_cmd('ll "/sdboot/up"')
        print(rst_debug)
        logger.console('ftp %s to %s' % (f_file[0],file_remote))
        ssh_lib.put_file(f_file[0], destination=file_remote, mode='0774', newline='')
        time.sleep(8)
        rst_debug=cli_cmd('ll "/sdboot/up"')
        print(rst_debug)
        rst=cli_cmd('ll "/sdboot/up/*.bin"')
        list=rst.split(' ')

        #check .bin file
        print(str(size_local))
        if str(size_local) not in list:
            raise FatalError('file size is error,local:%s != remote: %s' % (size_local,size_remote))
    except CmdError, cmd_msg:
        logger.error(cmd_msg)
        raise
    except AssertionError, ast_msg:
        logger.error(ast_msg)
        #cli_close()
        raise
    except Exception,ex_msg: 
        logger.error(ex_msg)
        raise 
    else:
        logger.info('FTP Version Done!',also_console=True)


def cli_npt_switch_mode(mode):
    '''des:switch cli mode    \n
    mode:config/oper/shell    \n
    '''
    output=""
    ip_keys=ssh_lib.get_connection().alias
    Connectinfo=DICT_HOST.get(ip_keys)
    logger.info(DICT_HOST) 
    src_mode=Collections().get_from_dictionary(Connectinfo,"mode")
    user=Collections().get_from_dictionary(Connectinfo,"user")
    src_ip=Collections().get_from_dictionary(Connectinfo,"ip")
    logger.info(user) 
    logger.info(mode) 
    if user =="root":
        if src_mode=="oper":
            if mode == "config":
                output=cli_cmd('en')
                logger.console("output:",output) 
            elif mode == "shell":
                output=cli_cmd('en')
                output=cli_cmd('sw sh')
            else:
                pass
        elif src_mode =='config':
            if mode == 'shell':
                output=cli_cmd('sw sh')
            elif mode == 'oper':
                cli_close()
                cli_npt_login(src_ip)
            else:
                pass
        elif src_mode =='shell':
            if mode == "config":
                output=cli_cmd('exit')
            elif mode == "oper":
                cli_close()
                cli_npt_login(src_ip)
            elif mode == 'shell':
                pass
        else:
            pass
    Collections().set_to_dictionary(Connectinfo,"mode",mode)
    

def cli_npt_telnet_standby(ip):
    ''' telete to preparation board, clear standby sddata'''
    try:
        cli_npt_switch_mode('shell')
        output1 = cli_cmd('ifconfig')
        print(output1)
        #standby_output = String().get_lines_matching_pattern(output1,'*169.254.1.3*|*169.254.1.2*')
        if output1.find('inet 169.254.1.2') >=0:
            standby_ip = '169.254.1.3'
        elif output1.find('inet 169.254.1.3') >= 0:
            standby_ip = '169.254.1.2'
        else:
            raise AssertionError
        
        #telnet to standby card
        print(standby_ip)
        #cli_cmd('exit')
        cli_close()
        cli_npt_login(ip)
        cli_cmd('en')
        cli_cmd('sw ou')
        cli_cmd('ECHO ON')
        #cli_cmd('telnet ' + standby_ip)
        #cli_cmd('root')
        #cli_cmd('root')
        cmd_in=ssh_lib.write('telnet ' + standby_ip)
        time.sleep(2)
        print("telnet")
        cmd_in=ssh_lib._write(text='root',add_newline='True')
        time.sleep(2)
        cmd_in=ssh_lib._write(text='root',add_newline='True')
        time.sleep(2)
        #print(cli_cmd('who'))
        #stdin,stdout,stderr = ssh.exec_command('who')
        #cli_cmd("who")
        #print("who")
        #return 0
        #check local file
        #~ file_remote='/sdboot/up/' + netype + '_Emb.bin'
        #~ print(netype)
        #~ file_local=netype + '_Emb_' + '[0-9][0-9]*.bin'
        #~ f_file=glob.glob(dir_local + '/' + file_local)
        #~ print(f_file)
        #~ le=len(f_file)
        #~ if len(f_file)!=1:
            #~ raise AssertionError('file number is %d:%s' % (len(f_file),f_file) )
        #~ size_local=os.path.getsize(f_file[0])
        #~ print(size_local)
        
        #delete standby old .bin file
        #print(cli_cmd('pwd'))
        #~ print(0)
        #~ cmd_in=ssh_lib._write(text='cd "/sdboot/up"',add_newline='True')
        #~ print(1)
        #~ #print(cli_cmd('ls "/sdboot/up"'))
        #~ cmd_in=ssh_lib._write(text='rm ' + "file_remote",add_newline='True')
        #~ print(2)
        #~ time.sleep(3)
        
        #put version
        #~ logger.console('ftp %s to %s' % (f_file[0],file_remote))
        #~ ssh_lib.put_file(f_file[0], destination=file_remote, mode='0774', newline='')
        #~ time.sleep(5)
        #~ cmd_in=ssh_lib._write(text='ll "sdboot/up/*.bin"',add_newline='True')
        #cmd_out=ssh_lib.read()
        #rst=cli_cmd('ll "/sdboot/up/*.bin"')
        #list=cmd_out.split(' ')
        
        #check .bin file
        #~ print(str(size_local))
        #~ if str(size_local) not in list:
            #~ raise FatalError('file size is error,local:%s != remote: %s' % (size_local,size_remote))
        
        #clear standby sddata
        cmd_in=ssh_lib._write(text='en',add_newline='True')
        cmd_in=ssh_lib._write(text='sw sh',add_newline='True')
        cmd_in=ssh_lib._write(text='cd "/sddata"',add_newline='True')
        #~ cmd_in=ssh_lib.write('ls')
        cmd_in=ssh_lib._write(text='xdelete "/sddata"',add_newline='True')
        #~ output2=ssh_lib.read()
        #~ list_output2 = output2.split(' ')
        #~ for i in range (len(list_output2)):
            #~ cmd_in=ssh_lib.write('xdelete ' + '"' + list_output2[i] + '"')
        #~ else:
            #~ cmd_in=ssh_lib.write('cd "/sddata"')
            #~ cmd_in=ssh_lib.write('ll')
            #~ output1=ssh_lib.read()
            #~ list_test = output1.split(' \r\n')
            #~ print(list_test)
            #~ if len(list_test) == 1:
                #~ print('Standby Configuration deleted successfully!')
            #~ else:
                #~ raise AssertionError
                #~ print('Files not completely deleted, Please check it!')
    except CmdError, cmd_msg:
        logger.error(cmd_msg)
        raise
    except AssertionError, ast_msg:
        logger.error(ast_msg)
        #cli_close()
        raise
    except Exception,ex_msg: 
        logger.error(ex_msg)
        raise 
    else:
        logger.info('Standby Done!',also_console=True)


def cli_npt_file_ftp(dir_local,netype='NPT1200'):
    '''des:ftp lct from dir_local to /sdlog of NE   \n
    dir_local:   D:/Version/LctBootInfo  \n
    or:			D:/Version/startup  \n
    '''
    try:
        cli_npt_switch_mode("shell")
        if dir_local == 'D:/Version/LctBootInfo' :
            file_remote='/sdlog/LctBootInfo'
            file_local='LctBootInfo'
            f_file=glob.glob(dir_local + '/' + file_local)
            le=len(f_file)
            if len(f_file)!=1 :
                raise AssertionError('file number is %d:%s' % (len(f_file),f_file) )
            #check if LctBootInfo file exist
            cli_cmd('cd "/sdlog"')
            print(cli_cmd('pwd'))
            #put LctBootInfo file
            logger.console('ftp %s to %s' % (f_file[0],file_remote))
            print("666")
            ssh_lib.put_file(f_file[0], destination=file_remote, mode='0774', newline='')
            print('666')
            rst=cli_cmd('ll "/sdlog"')
            list=rst.split(' ')
            if 'LctBootInfo' in list :
                print('The file %s exist!' % file_local)
            if 'LctBootInfo' not in list :
                raise FatalError('The file %s is not existed!' % file_local)
                print('The file transfer failed!')
        elif dir_local == 'D:/Version/startup':
            file_remote = '/sdboot'
            file_local = 'startup'
            if netype == 'NPT1200':
                dir_local = 'D:/Version/startup/NPT1200'
            elif netype == 'NPT1050':
                dir_local = 'D:/Version/startup/NPT1050'
            elif netype == 'NPT1020':
                dir_local = 'D:/Version/startup/NPT1020'
            elif netype == 'NPT1010':
                dir_local = 'D:/Version/startup/NPT1010'
            elif netype == 'NPT1010D':
				dir_local = 'D:/Version/startup/NPT1010D'
            else:
                raise Exception('There is no corresponding type of startup file! Please check it!')
            f_file = glob.glob(dir_local + '/' + file_local)
            le =len(f_file)
            if len(f_file) != 1:
                raise AssertionError('file number is %d:%s' % (len(f_file),f_file) )
            
            #delete old startup file
            cli_cmd('cd "/sdboot"')
            #print(cli_cmd('ls'))
            output = cli_cmd('rm "startup"')
            output_list = output.split(' ')
            if 'startup' in output:
                raise AssertionError('delete startup failed!')
            else:
                print('delete startup!')
            
            #put startup file
            logger.console('ftp %s to %s' % (f_file[0],file_remote))
            ssh_lib.put_file(f_file[0], destination=file_remote, mode='0774', newline='')
            rst=cli_cmd('ll "/sdboot"')
            list = rst.split(' ')
            if 'startup' in list:
                print('startup exist!')
            if 'startup' not in list:
                raise FatalError('The startup file is not existed! Please fixed it!')
    except CmdError, cmd_msg:
        logger.error(cmd_msg)
        raise
    except AssertionError, ast_msg:
        logger.error(ast_msg)
        raise 
    except Exception,ex_msg:
        logger.error(ex_msg)
        raise
    else:
        logger.console('FTP File Done!')
        logger.info('FTP File Done!')


def cli_npt_rm_sddata():
    '''delete all the files in the sddata folder'''
    try:
        cli_npt_switch_mode("shell")
        cli_cmd('cd ' + '"/sddata"')
        output2=cli_cmd('ls')
        #print(output2)
        list2 = output2.split(' \r\n')
        #print(list2)
        for i in range(len(list2)):
            print "%s,%s" % (i,list2[i])
            cli_cmd('xdelete ' + '"' + list2[i] + '"')
        else:
            cli_cmd('cd ' + '"/sddata"')
            output1 = cli_cmd('ll')
            list_test = output1.split(' \r\n')
            print(list_test)
            if len(list_test) == 1:
                print('Configuration deleted successfully!')
            else:
                raise AssertionError
                print('Files not completely deleted, Please check it!')
                
    except AssertionError,ast_msg:
        logger.error(ast_msg)
        raise
    except CmdError, cmd_msg:
        logger.error(cmd_msg)
        raise
    except Exception,ex_msg:
        logger.error(ex_msg)
        raise
    else:
        logger.console('Delete Done!')
        logger.info('Delete Done!')


def cli_get_ne_info(get_type=''):
    try:
        ne_info={}
        if get_type=='ne_type' or get_type=='':
            #get ne_type
            rst=cli_cmd('ls -l /sdboot/up/*.bin')
            type_list=cli_get_regrex(rst,'up/(.*)_Emb.bin')
            type_str=type_list[0]
            if type_str=='NPT1800':
                ne_type='NPT1800'
            elif type_str=='NPT1200i':
                ne_type='NPT1200i'
            else:
                raise AssertionError(type_str)
            ne_info['ne_type']=ne_type
        if get_type=='ne_mode' or get_type=='':
            #get standby_ip and ne_mode
            rst=cli_cmd('arp')
            standby_str=String().get_lines_matching_regexp(rst,'\\b169.254.1.3\\b.*|\\b169.254.1.2\\b.*')
            if standby_str=='' :
                ne_mode='2+0'
                standby_ip=''
            elif standby_str.find('incomplete')>0 :
                ne_mode='1+0'
                standby_ip=''
            elif standby_str.find('169.254.1.3')>=0 :
                ne_mode='1+1'
                standby_ip='169.254.1.3'
            elif standby_str.find('169.254.1.2')>=0 :
                ne_mode='1+1'
                standby_ip='169.254.1.2'
            else :
                raise AssertionError(rst)
            ne_info['ne_mode']=ne_mode
            ne_info['standby_ip']=standby_ip

    except CmdError, cmd_msg:
            logger.error(cmd_msg)
            raise
    except AssertionError, ast_msg:
            logger.error(ast_msg)
            #cli_close()
            raise 
    except Exception,ex_msg: 
            raise 
    else:
        if get_type=='':
            return ne_info
        else:
            return ne_info[get_type]
            

def cli_check_system(nemode='1+1',loop=10):
    '''des:Check system status if Up and check all cs/ms cards if Up   \n
    nemode=1+1/1+0/2+0   \n
    loop=10  wait 60s and loop times if down   \n
    '''
    try:
        # ne_info=cli_get_ne_info()
        # cli_cmd('lsh')
        # cli_cmd('config')
        # nemode=ne_info['ne_mode']
        cli_check_cmd('run show system status','System Operational Status : Up|System Operational State : Up',loop,interval=60)
        if nemode=='1+1':
            cli_check_cmd('run show chassis status','(\\bmsa|xsa\\b).*\\bUp\\b',loop,interval=60)
            cli_check_cmd('run show chassis status','(\\bmsb|xsb\\b).*\\bUp\\b',loop,interval=60)
            cli_check_cmd('run show chassis status','\\bcsa\\b.*\\bUp\\b',loop,interval=60)
            cli_check_cmd('run show chassis status','\\bcsb\\b.*\\bUp\\b',loop,interval=60)
        else:
            cli_check_cmd('run show chassis status','(\\bcsa|csb\\b).*\\bUp\\b',loop,interval=60)
            cli_check_cmd('run show chassis status','(\\bmsa|msb|xsa|xsb\\b).*\\bUp\\b',loop,interval=60)
    except (CmdError,FatalError):
        raise  
    except Exception,ex_msg: 
        raise CmdError(ex_msg) 
    else:
        logger.info('System Up!')
        
def cli_ftp_version(dir_local,netype='NPT1800',nemode='1+1'):
    '''des:ftp version from dir_local to /sdboot/up of NE   \n
    dir_local:   D:/Version/  \n
    netype=NPT1800/NPT1050i/NPT1200i    \n
    nemode=1+1/1+0/2+0  \n
    '''
    try:
        # ne_info=cli_get_ne_info()
        # nemode=ne_info['ne_mode']
        # netype=ne_info['ne_type']
        cli_switch_mode("shell")
        file_remote='/sdboot/up/' + netype + '_Emb.bin'
        if nemode=='2+0' :
            file_local=netype + '_Emb_2p0_' + '[0-9][0-9]*.bin' 
        else:
            file_local=netype + '_Emb_' + '[0-9][0-9]*.bin'
        f_file=glob.glob(dir_local + '/' + file_local)
        if len(f_file)!=1 :
            raise CmdError('file number is %d:%s' % (len(f_file),f_file) )
        size_local=os.path.getsize(f_file[0])
        
        cli_cmd('su - root')
        #cli_cmd('rm *.old')
        #cli_cmd('chown admin:users ' + file_remote)
        #cli_cmd('chmod 777 ' + file_remote)
        cli_cmd('rm ' + file_remote + '.old')
        cli_cmd('mv ' + file_remote +' ' + file_remote + '.old')
        cli_cmd('exit')
        
        #put version
        logger.console('ftp %s to %s' % (f_file[0],file_remote))
        ssh_lib.put_file(f_file[0], destination=file_remote, mode='0774', newline='')
        rst=cli_cmd('ls -l /sdboot/up/*.bin')
        list=rst.split(' ')
        size_remote=list[4]
        if str(size_local)!=str(size_remote) :
            raise FatalError('file size is error,local:%s != remote: %s' % (size_local,size_remote))
            #print('file size is error,local:%s != remote: %s' % (size_local,size_remote))
        cli_cmd('sync','nocheck')
        
        #check version
        
        #exit to linux
    except (CmdError,FatalError):
        raise
    except Exception,ex_msg: 
        raise CmdError(ex_msg)  
    else:
        logger.info('ftp version Done!')
        
def cli_export_cli(ne_ip,cli_string,file="C:/NPTI_CLI/report/ne_conf"):

    '''des:run cli_string and then export to local dir ${file}   \n
    ne_ip:      \n
    cli_string:run show configuration;run show configuration|display-set '\<ts1\>'  \n
    file=C:/NPTI_CLI/report/ne_conf         \n
    '''
    try:
        cli_list=cli_string.split(";")
        cli_login(ne_ip,mode='config')
        case_name=BuiltIn().get_variable_value("${TEST NAME}")
        suite_name=BuiltIn().get_variable_value("${SUITE NAME}")
        file_name=ne_ip + "_" + suite_name + "_" + case_name + ".txt"
        file_name=file_name.replace(' ','_')
        file_name=file_name.replace(':','_')
        cli_one=cli_list[0]
        cli_count=len(cli_list)
        cli_cmd(cli_list[0] + "|save /sdlog/" + file_name)
        for i in range(1,cli_count):
            cli_cmd(cli_list[i] + "|append /sdlog/" + file_name)
        ssh_lib.get_file("/sdlog/" + file_name, file + "//" + file_name)
    except Exception,ex_msg:
        #logger.error(ex_msg)
        raise CmdError(ex_msg)          
        
def cli_export_log(ne_type,ne_name,level,des_path,src_path='/var/log/log_collection'):
    '''des: auto export NE logs at des_path, which define at topo_var.py.   \n
    ne_type: '1800' '1200'    \n
    ne_name:            \n
    level=${SUITE NAME} ${TEST NAME}    
    des_path: r'D:\Version\auto_log'   \n
    src_path='/var/log/log_collection'   \n
    '''
    if LOG_FLAG == 'true':
        try:
            if not os.path.exists(des_path):
                os.mkdir(des_path)
            #export logs
            if ne_type.find('1800') != -1:
                cli_cmd('run request support log-collection')
                #export mcp log
                logger.info('Begin export 1800 logs .')
                cli_cmd('1')
                src_mcp_file = src_path + '/mcp*.tar.gz'
                mcp_name = ne_name + '-mcp-' + level + '.tar.gz'
                des_mcp_file = os.path.join(des_path,mcp_name)
                logger.info('Ready for 1800 MCP logs. Src_File: %s, Des_File: \
                        %s' % (src_mcp_file, des_mcp_file))
                ssh_lib.get_file(src_mcp_file, des_mcp_file)
                #exprot cips log
                cli_cmd('2')
                src_cips_file = src_path + '/cips*.tar.gz'
                cips_name = ne_name + '-cips-' + level + '.tar.gz'
                des_cips_file = os.path.join(des_path,cips_name)
                logger.info('Ready for 1800 CIPS logs. Src_File: %s, Des_File: \
                        %s' % (src_cips_file, des_cips_file))
                ssh_lib.get_file(src_cips_file, des_cips_file)
                #exit log_collection
                cli_cmd('9')
            elif ne_type.find('1200') != -1:
                cli_cmd('run request support log-collection')    
                #export mcp log
                logger.info('Begin export 1200 logs .')
                cli_cmd('1')
                src_mcp_file = src_path + '/mcp*.tar.gz'
                mcp_name = ne_name + '-mcp-' + level + '.tar.gz'
                des_mcp_file = os.path.join(des_path,mcp_name)
                logger.info('Ready for 1200 MCP logs. Src_File: %s, Des_File: \
                        %s' % (src_mcp_file, des_mcp_file))
                ssh_lib.get_file(src_mcp_file, des_mcp_file)
                #exit log_collection
                cli_cmd('8')
            elif ne_type.find('1300') != -1:
                cli_cmd('run request support log-collection')    
                #export mcp log
                logger.info('Begin export 1300 logs .')
                cli_cmd('1')
                src_mcp_file = src_path + '/mcp*.tar.gz'
                mcp_name = ne_name + '-mcp-' + level + '.tar.gz'
                des_mcp_file = os.path.join(des_path,mcp_name)
                logger.info('Ready for 1300 MCP logs. Src_File: %s, Des_File: \
                        %s' % (src_mcp_file, des_mcp_file))
                ssh_lib.get_file(src_mcp_file, des_mcp_file)
                #exit log_collection
                cli_cmd('8')
            elif ne_type.find('1050') != -1:
                cli_cmd('run request support log-collection')
                #export mcp log
                logger.info('Begin export 1050 logs .')
                cli_cmd('1')
                src_mcp_file = src_path + '/mcp*.tar.gz'
                mcp_name = ne_name + '-mcp-' + level + '.tar.gz'
                des_mcp_file = os.path.join(des_path,mcp_name)
                logger.info('Ready for 1050 MCP logs. Src_File: %s, Des_File: \
                        %s' % (src_mcp_file, des_mcp_file))
                ssh_lib.get_file(src_mcp_file, des_mcp_file)
                #exit log_collection
                cli_cmd('8')
            else:
                #logger.error()
                raise CmdError('Input Error, Please enter NE Type!')
        except (CmdError,FatalError):
            raise
        except Exception,ex_msg:
            #logger.error(ex_msg)
            raise CmdError(ex_msg)
    else:
        pass
            
def cli_export_teq(level,des_path):
    if TEQ_FLAG=='true' :
        try:
            if not os.path.exists(des_path):
                os.mkdir(des_path)
            noblanklevel = level.replace(' ','-')
            standlevel = noblanklevel.replace('.','-')
            teq_name = standlevel + '.xml'
            teq_path = os.path.join(des_path,teq_name)
            tcl_teq_path = teq_path.replace(os.sep, '/')
            logger.info('Ready for Export Teq. Des_File: %s' % tcl_teq_path)
            tcl_send('tcl_SPT_ExportAll %s' % tcl_teq_path)
        except (CmdError,FatalError):
            raise
        except Exception,ex_msg:
            #logger.error(ex_msg)
            raise CmdError(ex_msg)
    else:
        pass


          


        
def cli_reset_clear(nemode='1+1',reset_tpye='no-recovery-sdh',ver='7.0'):
    '''des:reset ne and close ssh session   \n
    nemode=1+1/1+0/2+0  \n
    reset_tpye=no-recovery-sdh/force/run request reset ne   \n
    '''
    try:
        cli_switch_mode("shell")
        cli_cmd('su - root')
        if nemode=='1+1':
            rst=cli_cmd('arp')
            standby_str=String().get_lines_matching_regexp(rst,'\\b169.254.1.3\\b.*|\\b169.254.1.2\\b.*')
            if standby_str.find('169.254.1.3')>=0 :
                standby_ip='169.254.1.3'
            elif standby_str.find('169.254.1.2')>=0 :
                standby_ip='169.254.1.2'
            else :
                raise CmdError(rst)
    
        #clear config
        if reset_tpye=='force' :
            if nemode=='1+1':
                cli_cmd('telnet ' + standby_ip)
                cli_cmd('root')
                cli_cmd('cd /sddata')
                cli_cmd('rm -f -r *')
                cli_cmd('cd /sdlog')
                cli_cmd('rm -f -r *')
                cli_cmd('sync')
                cli_cmd('reboot')
                time.sleep(3)
                cli_cmd('ls')

            cli_cmd('cd /sddata')
            cli_cmd('rm -f -r *')
            cli_cmd('cd /sdlog')
            cli_cmd('rm -f -r *')
            cli_cmd('sync')
            cli_cmd('reboot')
            time.sleep(1)
            cli_close()
        elif reset_tpye=='no-recovery-sdh':
            if nemode=='1+1':
                cli_cmd('telnet ' + standby_ip) # if failed:???
                cli_cmd('root')
                cli_cmd('cd /sdlog')
                cli_cmd('rm -f -r *')
                cli_cmd('sync')
                cli_cmd('exit')
                pass
            cli_cmd('cd /sdlog')
            cli_cmd('rm -f -r *')
            cli_cmd('sync')
            cli_cmd('exit') # for root
            cli_switch_mode("config")
            cli_cmd('run show version')
            if ver=='6.1':
                cli_cmd('run request reset no-recovery-sdh')    
                cli_cmd('yes')
            else:
                cli_cmd('run request debug "no-recovery-reset sdh keep_rid"')            
            cli_cmd('run show version detail')
            time.sleep(1)
            cli_cmd('run show version detail')
            time.sleep(1)
            #cli_cmd('y')
            cli_close()
        else:
            cli_cmd('exit') # for root
            cli_switch_mode("config")
            cli_cmd('run request reset ne')
            cli_cmd('y')
            time.sleep(1)
            cli_close()
    except (CmdError,FatalError):
        raise
    except Exception,ex_msg: 
        raise CmdError(ex_msg)
    else:
        logger.console('Clear Done,Rebot NE...')
        


def cli_cmd(cmd,msg=''):
    '''des:send config/opeartion/shell cli to ne and get result    \n
    cmd:run show version/set xxxx/commit/show version/ls etc   \n%s
    msg:
    '''
    if (DELETE_FLAG=='false') and (cmd.find('delete ')==0) :
        logger.debug('Not Delete DELETE_FLAG: %s, \ncmd: %s' % (DELETE_FLAG, cmd))
        pass
    else:
        try:
            #a='a'+1
            #print('*INFO* debug_befor:%s *INFO*'  %ssh_lib.read())
            logger.debug('cmd_before:%s *END*' %ssh_lib.read())
            #print(aaa)
            # modify cmd to cmd_new
            if cmd.find('show')==0 or cmd.find('run show')==0 :
                if cmd.find('|save ')==-1 and cmd.find('|append ')==-1:
                    cmd_new=cmd+'|no-more'
                else:
                    cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=180)
            elif cmd=='commit':
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=600)
            elif cmd=='yes_commit' :
                cmd_new='yes'
                ssh_lib.set_client_configuration(timeout=600)
            elif cmd=='sync':
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=600)
            elif cmd.find('bsp_sftp ')==0:
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=180)
            elif cmd.find('run ping ')==0:
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=60)
            elif cmd.find('run traceroute ')==0:
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=60)
            elif cmd=='y':
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=60)
            elif cmd.find('rm -f ')==0:
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=60)
            else:
                cmd_new=cmd
                ssh_lib.set_client_configuration(timeout=10)
            #send cmd_new   
            cmd_in=ssh_lib.write(cmd_new)
            #print('debug:' + cmd_in)
            #modify reg_prompt 
            if cmd_new=='sync' and msg=='nocheck':
                logger.info('sync....nocheck')
                return 'sync,nocheck'
            elif cmd_new.find('exit')==0:
                reg_prompt='.*@.*(>|#) $| \(yes\) | \(no\) |logout |root> $|root# $|-> $|Au.*$'
            elif cmd_new.find('telnet ')==0:
                print(cmd_new)
                return 0
            elif cmd_new=='run request support log-collection' or cmd_new=='1' or cmd_new=='2' or cmd_new=='3' or cmd_new=='4' or cmd_new=='5' or cmd_new=='6':
                reg_prompt='Enter the Menu Number : '
                if cmd_new=='1' or cmd_new=='2':
                    ssh_lib.set_client_configuration(timeout=600)
                else:
                    ssh_lib.set_client_configuration(timeout=60)
            else:
                #reg_prompt='.*@.*(>|#) $|.*$ |.*> |.*:~\$ $| \(yes\) | \(no\) '
                #.*@.*(>|#) $   admin@npt1800> root@1800# root@npt1800:~#
                #.*:~\$ $   npt1800:~$ npt1800:/sdlog$
                reg_prompt='.*@.*(>|#) $|.*:.*\$ $|.*bash.*(#|\$) $| \(yes\) | \(no\) $|root> $|root# $|-> $|Debug.*$'
            cmd_out=ssh_lib.read_until_regexp(reg_prompt)
        except Exception ,ex_msg:
            rsf=1
            #print('aaa ' + dir(ex_msg) +' aaa')
            if str(ex_msg).find('Socket is closed')>=0:
                cli_close('')
                #print('abc')
            #logger.error(ex_msg)
            raise CmdError(repr(ex_msg))
            
        else:
            if cmd_out.find('!!! RCP is not Active, functionality is limited !!!') >=0 :
                rst ='Fatal_CmdError: ' + cmd_out
            elif cmd_out.find('cfgd process not responding') >=0:
                rst ='Fatal_CmdError: ' + cmd_out
            elif cmd_out.find('ERROR: cml process appears to have died:') >=0:
                rst ='Fatal_CmdError: ' + cmd_out
            elif cmd_out.find(': command not found')>=0:
                rst='Linux_CLI_Error: ' + cmd_out
            elif cmd_out.find('syntax error, ')>=0:
                #abc
                rst='lsh/config_CLI_Error: ' + cmd_out
            elif cmd_out.find('error: unknown argument')>=0:
                #set cli screen-width abc
                rst='lsh_CLI_Error: ' + cmd_out
            elif cmd_out.find('error: missing required argument')>=0:
                #set cli screen-width
                rst='lsh_CLI_Error: ' + cmd_out
            elif cmd_out.find('error: unknown command')>=0:
                #abc
                rst='config_CLI_Error: ' + cmd_out
            elif cmd_out.find('error: file not found')>=0:
                rst='Linux_CLI_Error: ' + cmd_out
            elif cmd_out.find('Exit with uncommitted changes')>=0:
                # new_cmd_in=ssh_lib.write('yes')
                # new_cmd_out=ssh_lib.read_until_regexp(reg_prompt)
                # rst="exit config:" + new_cmd_out
                rst=cmd_out
            else:
                rst=cmd_out
            if msg=='':
                if rst.find('Fatal_CmdError:')>=0:
                    rsf=1               
                    #logger.error('%s ->\n%s' %(cmd_new,rst))                
                    raise FatalError('%s ->\n%s' %(cmd_new,rst))
                elif rst.find('_CLI_Error: ')>=0:
                    rsf=1               
                    #logger.error('%s ->\n%s' %(cmd_new,rst))                
                    raise CmdError('cli_cmd %s ->\n%s' %(cmd_new,rst))
                elif cmd_new=='commit' or cmd=='yes_commit':
                    if rst.find('commit failed')>=0 :
                        cli_cmd('rollback')
                        #cli_cmd('commit')
                        rsf=1               
                        #logger.error('%s ->\n%s' %(cmd_new,rst))                
                        raise CmdError('%s ->\n%s' %(cmd_new,rst))
                    elif rst.find('Do you wish to continue with the commit?')>=0 :
                        cli_cmd('yes_commit')
                        #rsf=0
                    else:               
                        rsf=0
                        #logger.debug('%s ->\n%s' %(cmd_new,rst))
                        return rst              
                else:
                    rsf=0
                    #logger.debug('%s ->\n%s' %(cmd_new,rst))
                    return rst
            elif msg==rst:
                rsf=0
                #logger.debug('%s ->\n%s\n == %s' %(cmd_new,rst,msg))
                return rst
            else:
                rsf=1
                #logger.error('%s ->\n%s\n != %s' %(cmd_new,rst,msg))
                raise CmdError('%s ->\n%s\n != %s' %(cmd_new,rst,msg))

def _cli_upgrade(dir_local,netype='1800',nemode='1+0',upgrade_mode='no-recovery-sdh'):
    '''des: \n
    dir_local=d:/version    \n
    netype=1800/1200i   \n
    nemode=2+0/1+0/1+1  \n
    upgrade_mode=no-recovery-sdh/force/reset
    '''
    try:
        #cli_login(ip)
        #get version
        #ssh_lib.directory_should_exist("/sdboot/up")
        cli_cmd('ls -l /sdboot/up')
        file_remote='/sdboot/up/' + 'NPT' + netype + '_Emb.bin'
        if nemode=='2+0' :
            file_local='NPT' + netype + '_Emb_2p0_' + '[0-9][0-9]*.bin' 
        else:
            file_local='NPT' + netype + '_Emb_' + '[0-9][0-9]*.bin'
        f_file=glob.glob(dir_local + '/' + file_local)
        if len(f_file)!=1 :
            raise AssertionError('file number is %d:%s' % (len(f_file),f_file) )
        size_local=os.path.getsize(f_file[0])
        #put version
        logger.console('ftp %s to %s' % (f_file[0],file_remote))
        ssh_lib.put_file(f_file[0], destination=file_remote, mode='0744', newline='')
        rst=cli_cmd('ls -l /sdboot/up/*.bin')
        list=rst.split(' ')
        size_remote=list[4]
        if str(size_local)!=str(size_remote) :
            raise AssertionError('file size is error,local:%s != remote: %s' % (size_local,size_remote))
            #print('file size is error,local:%s != remote: %s' % (size_local,size_remote))
        cli_cmd('sync')
        #clear config
        if upgrade_mode=='force' :
            cli_cmd('cd /sddata')
            cli_cmd('rm -f -r *')
            cli_cmd('cd /sdlog')
            cli_cmd('rm -f -r *')
            cli_cmd('sync')        
            if nemode=='1+1':
                standby_ip=''
                rst=cli_cmd('arp')
                standby_str=String().get_lines_containing_string(rst,'169.254.1.3')
                if standby_str.find('ether')>0 :
                    standby_ip='169.254.1.3'
                standby_str=String().get_lines_containing_string(rst,'169.254.1.2')
                if standby_str.find('ether')>0 :
                    standby_ip='169.254.1.2'
                #rm /root/.ssh/known_hosts in main card
                #bsp_sftp -H root -X "/sdboot/up/NPT1800_Emb.bin /sdboot/up/NPT1800_Emb.bin" root@169.254.1.3
                if standby_ip=='169.254.1.2' or standby_ip=='169.254.1.3' :
                    ftp_cmd='bsp_sftp -H root -X "' + file_remote + ' ' + file_remote + '" root@' + standby_ip
                    cli_cmd(ftp_cmd)
                    cli_cmd('telnet ' + standby_ip)
                    cli_cmd('root')
                    cli_cmd('cd /sddata')
                    cli_cmd('rm -f -r *')
                    cli_cmd('cd /sdlog')
                    cli_cmd('rm -f -r *')
                    cli_cmd('sync')
                    cli_cmd('reboot')
                    #cli_cmd('exit')
                else:
                    raise AssertionError('standby_ip %s is error in 1+1 mode' % standby_ip )
            time.sleep(3)
            cli_cmd('')
            cli_cmd('')
            cli_cmd('reboot')
            cli_close()
        elif upgrade_mode=='no-recovery-sdh':
            if nemode=='1+1':
                standby_ip=''
                rst=cli_cmd('arp')
                standby_str=String().get_lines_containing_string(rst,'169.254.1.3')
                if standby_str.find('ether')>0 :
                    standby_ip='169.254.1.3'
                standby_str=String().get_lines_containing_string(rst,'169.254.1.2')
                if standby_str.find('ether')>0 :
                    standby_ip='169.254.1.2'
                #rm /root/.ssh/known_hosts in main card
                #bsp_sftp -H root -X "/sdboot/up/NPT1800_Emb.bin /sdboot/up/NPT1800_Emb.bin" root@169.254.1.3
                if standby_ip=='169.254.1.2' or standby_ip=='169.254.1.3' :
                    cli_cmd('telnet ' + standby_ip)
                    cli_cmd('root')
                    cli_cmd('cd /sdlog')
                    cli_cmd('rm -f -r *')
                    cli_cmd('sync')
                    cli_cmd('exit')
                else:
                    raise AssertionError('standby_ip %s is error in 1+1 mode' % standby_ip )
            cli_cmd('cd /sdlog')
            cli_cmd('rm -f -r *')
            cli_cmd('sync')
            cli_cmd('lsh')
            cli_cmd('request reset no-recovery-sdh')
            cli_cmd('y')
            cli_close()
        else:
            cli_cmd('lsh')
            cli_cmd('request reset ne')
            cli_cmd('y')
            cli_close()
    except CmdError, cmd_msg:
        logger.error(cmd_msg)
        raise
    except AssertionError, ast_msg:
        logger.error(ast_msg)
        #cli_close()
        raise 
    except Exception,ex_msg: 
        logger.error(ex_msg)
        raise 
    else:
        logger.console('Upgrade Done,Rebot NE...')

      
def cli_init(mode='robot'):
    '''des:init cli env   \n
    must run at first \n
    '''
    global ssh_lib,DICT_HOST
    DICT_HOST={}
    ssh_lib=SSHLibrary.SSHLibrary()
    
    global LOAD_MODE
    LOAD_MODE=mode
    lib_get_var()
    
    # if mode=='robot' :
        # lib_robot_var()
    # else :
        # lib_qtp_var()
    print(dir(ssh_lib))
def tcl_send_retry(tcl_fun,loop=3,wtime=3):
    if TEQ_FLAG=='true' :
        if tcl_fun.find('tcl_')==0 or tcl_fun.find('teq_')==0 :
            try:
                i=0
                while i<int(loop):
                    i=i+1
                    logger.info('the %i time sent tcl cmd...' % i,also_console=True)                
                    logger.info(tcl_fun,also_console=True)
                    rst = Tclsh.eval(tcl_fun)
                    if rst.find('0^')!=0:
                        rsf=1
                        logger.info(rst,also_console=True)
                        if i<int(loop):
                            #logger.info('wait and check tcl again...',also_console=True)
                            time.sleep(int(wtime))
                    elif rst.find('stcerror in perform: Lost connection')>0 or rst.find('stcerror in perform: Cannot create request:')>0:
                        rsf=1
                        raise FatalError('Fata_SPT_Error: ' + rst)
                    else:
                        #logger.info('ok...',also_console=True)
                        rsf=0
                        break
                if rsf==1:
                    #logger.info('end...',also_console=True)
                    raise TeqError(rst)
                else:
                    logger.info(rst,also_console=True)
            except (TeqError,FatalError):
                raise
            except Exception as ex_msg:
                raise CmdError(ex_msg)
        else:
            pass
    else:
        pass

def tcl_send(tcl_fun):
    '''des:send tcl functions in robot    \n
    tcl_fun: tcl_/teq_  \n
    '''
    if TEQ_FLAG=='true' :
        try:
            logger.info(tcl_fun,also_console=True)
            rst = Tclsh.eval(tcl_fun)
            if tcl_fun.find('tcl_')==0 or tcl_fun.find('teq_')==0 :
                if rst.find('0^')!=0:
                    raise TeqError(rst)
                elif rst.find('stcerror in perform: Lost connection')>0 or rst.find('stcerror in perform: Cannot create request:')>0:
                    raise FatalError('Fata_SPT_Error: ' + rst)
                else:
                    pass
            else:
                pass
        except TeqError:
            raise 
        except FatalError:
            raise
        except Exception as ex_msg: 
            raise CmdError(ex_msg)            
        else:
            logger.info(rst,also_console=True)
            #logger.info(rst)
    else:
        pass
        
def tcl_env(tcl_dir='default'):
    '''des:init tcl env for teq    \n
    TEQ_FLAG='true' in var file\n
    '''
    if TEQ_FLAG=='true' :
        global Tclsh 
        Tclsh = Tkinter.Tcl()
        sys_path=os.environ['Path']
        if sys_path.find('(x86)')>0:
            #64
            program_file= "C:/Program Files (x86)"
        else:
            #32
            program_file= "C:/Program Files"        
        if tcl_dir=='default':
            tcl_send('lappend auto_path ' + '{' + program_file + '/Mercury Interactive/QuickTest Professional/Tests/JavaAT/Function/Ixia}')          
        else:
            #{C:/JavaAT/Function/Ixia}
            tcl_send('lappend auto_path ' + tcl_dir)        
        

        #tcl_send('lappend auto_path ' + '{' + program_file + '/Ixia/Tcl/8.4.14.0/lib/tcl8.4}')
        #tcl_send('lappend auto_path ' + '{' + program_file + 'Ixia/Tcl/8.4.14.0/lib}')
        
        tcl_send('set agilentLib ' + '{' + program_file + '/VISA/VisaCom/GlobMgr.dll}')
        tcl_send('package req tcom')
        tcl_send('package req dict')
        tcl_send('package req registry')
        tcl_send('package req tcl_Lib')

        tcl_send('set Regkey {HKEY_CURRENT_USER\\TCLTest} ')
        tcl_send('set debugFlag 0')
        tcl_send('set GLB_log_level "error_level"')
        tcl_send('set runTeq_global 1')
        tcl_send('set GLOBAL_LOG_FLAG 0')
        tcl_send('set reportLog_main_chan "" ')
        tcl_send('set logFlag 0')
        tcl_send('set QTP_Flag 0')
        tcl_send('set debugFlag 0')
        tcl_send('set glb_osVersion $env(Path)')
        if SPT_FORCE=='true':
            tcl_send('set glb_spt_force 1')
        else:
            tcl_send('set glb_spt_force 0')
    else:
        logger.debug('Not test teq TEQ_FLAG: %s.' % TEQ_FLAG)

class ssh_cli1(object):
    '''des:
    for class
    '''
    def __init__(self):
        '''des:
        for init
        '''
        pass
    def login(self,ip,user='root',passwd='root',mode='config'):
        '''des:
        for init
        '''
        
        ssh_lib.open_connection('200.200.12.111',prompt=':~#')
        ssh_lib.set_client_configuration(width=100)
        c=ssh_lib.get_connection()
        print(c)
        
        c=ssh_lib.login('root','root')
        print(c)
        
        ssh_lib.write("ls /sdboot/up")
        ssh_lib.read_until_prompt()
        
        ssh_lib.write("lsh")
        ssh_lib.read_until_regexp('.*@.*> $')
        
        ssh_lib.write("config")
        ssh_lib.read_until_regexp('.*@.*# $')
        pass
        

    def get_connection(self, *args):
        """Can be overridden to use a custom connection."""
        return ssh_cliConnect(*args)
        

class ssh_cliConnect(object):
    def ssh_login(self):
        pass

def auto_copy_version(txt_name, ser_path, tar_path, scan_time=180):
    '''des:auto copy version from server, scan server 60 times   \n
    txt_name: '6.1.txt'  '7.0.txt'   \n
    ser_path: r'\\172.18.104.44\R&D TN China\R&D_Server\Version Management\Dev_Version\Version to V&V\AT'
    tar_path: r'D:\Version'   \n
    scan_time: 600   \n
    '''
    try:
        ne_ver_num=BuiltIn().get_variable_value("${ne_ver_num}")
        re_text = re.compile(txt_name)
        re_file = re.compile('.*?bin')
        for i in range(480):
            folder_list = os.listdir(ser_path)
            for f in folder_list:
                logger.info('File at folder: %s' % f)
                if re_text.search(f) :
                    if os.path.exists(tar_path):
                        shutil.rmtree(tar_path)
                        time.sleep(6)
                        os.mkdir(tar_path)
                    else :
                        os.mkdir(tar_path)
                    temp_path = os.path.join(ser_path, f)
                    time.sleep(3)
                    with open(temp_path, 'r') as d: 
                        get_path = d.read()
                    temp_path1 = get_path.strip('\n')
                    temp_path2 = temp_path1.strip(' ')
                    source_path = temp_path2.strip('\"')
                    #source_dir = detail.split('=')[1].strip()
                    logger.info('Get path : %s.' % source_path)
                    fold_list = os.listdir(source_path)
                    for e in fold_list:
                        if re_file.search(e):
                            source_files = source_path + os.sep + e
                            logger.info('Ready for copy file : %s.' % source_files)
                            shutil.copy(source_files, tar_path)
                    #source_path = ser_path + os.sep + source_dir
                    tar_file = os.path.join(ne_ver_num, "detail.txt")
                    with open(tar_file, 'w') as d:
                        d.write(source_path)
                    os.remove(temp_path)
                    rst='OK, Copy version success!'
                    rsf=0
                    logger.info('Copy Version ->\n%s' % rst)
                    return
            num=i+1
            logger.info('Wait version: %d times.' % num)
            time.sleep(int(scan_time))
        stime = int(scan_time)*480/3600
        rst='Wait %d hours, can not find version.' % stime
        rsf=1               
        logger.error('Get detail txt ->\n%s' % rst)              
        raise FatalError('Get detail txt ->\n%s' % rst)
    except (CmdError,FatalError):
        raise
    except Exception,ex_msg:
        rsf=1               
        #logger.error('Copy Version ->\n%s' % ex_msg)                
        raise FatalError('Copy Version ->\n%s' % ex_msg)

print('aaa')


def npt_auto_copy_version(txt_name, ser_path, tar_path, scan_time=180):
    '''des:auto copy version from server, scan server 60 times   \n
    txt_name: npt.txt \n
    ser_path: r'D:/Version/ser_path'
    tar_path: r'D:/Version/npt_ems'   \n
    scan_time: 600   \n
    '''
    try:
        re_text = re.compile(txt_name)
        re_file = re.compile('.*?bin')
        for i in range(480):
            folder_list = os.listdir(ser_path)
            print(1)
            for f in folder_list:
                print('File at folder: %s' % f)
                if re_text.search(f) :
                    if os.path.exists(tar_path):
                        shutil.rmtree(tar_path)
                        time.sleep(6)
                        os.mkdir(tar_path)
                    else :
                        os.mkdir(tar_path)
                    temp_path = os.path.join(ser_path, f)
                    logger.info(temp_path)
                    time.sleep(3)
                    with open(temp_path, 'r') as d: 
                        get_path = d.read()
                    temp_path1 = get_path.strip('\n')
                    temp_path2 = temp_path1.strip(' ')
                    source_path = temp_path2.strip('\"')
                    print('Get path : %s.' % source_path)
                    fold_list = os.listdir(source_path)
                    for e in fold_list:
                        if re_file.search(e):
                            source_files = source_path + os.sep + e
                            logger.info('Ready for copy file : %s.' % source_files)
                            shutil.copy(source_files, tar_path)
                    #os.remove(temp_path)
                    rst='OK, Copy version success!'
                    rsf=0
                    print('Copy Version ->\n%s' % rst)
                    return
            num=i+1
            print('Wait version: %d times.' % num)
            time.sleep(int(scan_time))
        stime = int(scan_time)*480/3600
        rst='Wait %d hours, can not find version.' % stime
        rsf=1               
        print('Get detail txt ->\n%s' % rst)              
        raise FatalError('Get detail txt ->\n%s' % rst)
    except Exception,except_msg:
        rsf=1               
        print('Copy Version ->\n%s' % except_msg)                
        raise FatalError('Copy Version ->\n%s' % except_msg)

print('bbb')



def cli_npt_check_sys_up(IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8):
	sys_list = [IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8]
	start = datetime.datetime.now()
	print(start)
	cli_npt_login(IP1,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP1)
	else:
		print('%s is waiting system ok' % (IP1))
	cli_npt_login(IP2,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP2)
	else:
		print('%s is waiting system ok' % (IP2))
	cli_npt_login(IP3,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP3)
	else:
		print('%s is waiting system ok' % (IP3))
	cli_npt_login(IP4,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP4)
	else:
		print('%s is waiting system ok' % (IP4))
	cli_npt_login(IP5,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP5)
	else:
		print('%s is waiting system ok' % (IP5))
	cli_npt_login(IP6,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP6)
	else:
		print('%s is waiting system ok' % (IP6))
	cli_npt_login(IP7,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP7)
	else:
		print('%s is waiting system ok' % (IP7))
	cli_npt_login(IP8,mode='shell')
	output1 = cli_cmd('ns')
	if 'SYS_STATUS_OK' in output1:
		sys_list.remove(IP8)
	else:
		print('%s is waiting system ok' % (IP8))
	print(sys_list)
	if len(sys_list) == 0:
		logger.console('All System is Up!')
		cli_close('all')
		return 0
	else:
		for i in range(len(sys_list)):
			print(sys_list[i])
			cli_npt_login(sys_list[i],mode='shell')
			while True:
				print('11')
				output = cli_cmd('ns')
				if 'SYS_STATUS_OK' in output:
					print('%s system is ok' % (sys_list[i]))
					break
				else:
					logger.console('waiting for 60s,try check it again...')
					time.sleep(60)
					continue
	end = datetime.datetime.now()
	print(end)
	logger.console('Total waiting time for the system up is: %s' % ((end-start).seconds))
	logger.console('All systems are up,continue...')
	cli_close('all')


if __name__ == '__main__':
    ssh_lib=SSHLibrary.SSHLibrary()
    #GLB_PROMPT_REG='(.*@.*(>|#) $)'
    cli_login('200.200.12.111')
    cli_cmd('run show version')
    print('__main__')
    ''' 
    import ssh_cli
    reload ssh_cli
    ssh_cli.cli_login('200.200.12.111')
    ssh_cli.cli_cmd('run show version')
    
print(ssh_cli.ssh_lib.get_connections())
print(ssh_cli.ssh_lib.get_connection())
print(ssh_cli.ssh_lib.open_connection('200.200.12.111',alias='12',prompt=':~#'))
print(ssh_cli.ssh_lib.login('root','root'))
print(ssh_cli.ssh_lib.close_connection())

print(ssh_cli.ssh_lib.close_all_connections())

print(ssh_cli.ssh_lib.get_connections())
print(ssh_cli.ssh_lib.get_connection())


print(ssh_cli.ssh_lib.open_connection('200.200.18.203',alias='18',prompt=':~#'))

print(ssh_cli.ssh_lib.switch_connection('18'))
print(ssh_cli.ssh_lib.login('root','root'))



print(ssh_cli.ssh_lib.switch_connection('12'))

print(ssh_cli.ssh_lib.switch_connection('18'))

String().get_regexp_matches

import os
print(os.sys.path)
os.sys.path.append('c:/npti_cli/lib')
os.sys.path.append('c:/npti_cli/case')
print(os.sys.path)


    >>> ssh_cli.cli_cmd('abc')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "C:\Python27\lib\site-packages\ssh_cli.py", line 276, in cli_cmd

      File "C:\Python27\lib\site-packages\SSHLibrary\library.py", line 1027, in write
        return self._read_and_log(loglevel, self.current.read_until_newline)
      File "C:\Python27\lib\site-packages\SSHLibrary\library.py", line 1223, in _read_and_log
        raise RuntimeError(e)
    RuntimeError: No match found for '
    ' in 6 seconds
    Output:
    .
    >>> ssh_cli.cli_cmd('abc')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "C:\Python27\lib\site-packages\ssh_cli.py", line 276, in cli_cmd

      File "C:\Python27\lib\site-packages\SSHLibrary\library.py", line 1026, in write
        self._write(text, add_newline=True)
      File "C:\Python27\lib\site-packages\SSHLibrary\library.py", line 1050, in _write
        self.current.write(text, add_newline)
      File "C:\Python27\lib\site-packages\SSHLibrary\abstractclient.py", line 278, in write
        self.shell.write(text)
      File "C:\Python27\lib\site-packages\SSHLibrary\pythonclient.py", line 118, in write
        self._shell.sendall(text)
      File "C:\Documents and Settings\Administrator\Application Data\Python\Python27\site-packages\
        sent = self.send(s)
      File "C:\Documents and Settings\Administrator\Application Data\Python\Python27\site-packages\
        return self._send(s, m)
      File "C:\Documents and Settings\Administrator\Application Data\Python\Python27\site-packages\
        raise socket.error('Socket is closed')
    socket.error: Socket is closed
a:
    !!! RCP is not Active, functionality is limited !!!
    root@npt1800:~# lsh
    ERROR: The system failed to find or parse the initial configuration.
           You should load and commit a working configuration, then restart
           the system.  Please note that your configuration changes will not
           take effect until you've restarted the system.
x:
commit started

No changes to commit.
ERROR: commit cancelled because device is becoming active.
   777    Please try again later.

[edit]
y:
    root@npt1800> show version 
    ######## [slot:msa][Active] ########
    Software Release   : V6.0.036
    Version            : trunk-ppc-st-rcpd-V6.0R42435
    Ne Type            : NPT-1800
    Date Created       : Fri Apr  7 17:42:35 2017
    File Hash          : NA

    err: get [slot:msb] mcp version have err !!!
x1:
Connection was reset.

        ssh_lib.write('abc')
        print(ssh_cli.ssh_lib.read_until_regexp('.*@.*> $|.*@.*# $|--More--| \(yes\) | \(no\) '))
        print(ssh_cli.ssh_lib.read())


'''
    
