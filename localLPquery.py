"""Download, store locally and parse LP data from web.

Allows for downloading, storage, parsing and searching of LP blobs.
"""
import lastpass, getpass
import re, os
import sys, getopt
import time

def getLPBlob(filename="fooba.bin",username="johndoe@nowhere.org",passwordIn='nothing',topt='-1',TimeTag=False,Search=False):
    """
    Download a new LP Blob from online and save locally.
    
    Keyword arguments:
    filename, username, passwordIn -- as named
    totp -- time-based onetime password
    TimeTag -- if True, time of day is attached to the saved filename
    Search -- if True, LP Blob is immediately opened for search & query
    """
    if passwordIn=='nothing':
        password=getpass.getpass('Enter LP Password: ')
    else:
        password=passwordIn
    if topt=='-1':
        mytotpnow=raw_input('Enter One Time Passcode: ')
    else:
        mytotpnow=topt
    if TimeTag:
        crcr=time.localtime()
        crcr=''.join(["%02d"%i for i in [crcr.tm_year,crcr.tm_yday,crcr.tm_hour,crcr.tm_min]])
    else:
        crcr=''
    filename=crcr + filename
    results=True
    try:
        myblob = lastpass.Vault.fetch_blob(username, password,multifactor_password=mytotpnow,blob_filename=filename)
        if Search:
            results=searchFileBlob(BlobIn=myblob,passwordIn=password,username=username)
    except:
        print "getLPBlob: Something went wrong fetching the blob from the web."
        results=False
    finally:
        del(password)
        del(passwordIn)
        del(myblob) 
    return results
	
def mixrange(s):
    """
    Split text of comma range eg 1-3,7,8 ==> [1,2,3,7,8]
    """
    r = []
    for i in s.split(','):
        if '-' not in i:
            r.append(int(i))
        else:
            l,h = map(int, i.split('-'))
            r+= range(l,h+1)
    return r

def searchFileBlob(filename="fooba.bin",username="johndoe@nowhere.org",passwordIn='nothing',FilterIn='-1',BlobIn=None,timeout=600):
    """
    Open, Parse and search LP data from local file repository
    
    Keyword arguments:
    filename, username, passwordIn -- as named
    FilterIn -- used as initial search filter[optional]
    BlobIn -- passes in a LP Blob object instead of opening local file
    timeout -- vault automatically closes after timeout seconds of inactivity or after 6*timeout secs of total time
    """
    if FilterIn == '-1':
        Filter=raw_input("Enter Search Filter: ")
    else:
        Filter=FilterIn
    if passwordIn=='nothing':
        password=getpass.getpass('Enter LP Password: ')
    else:
        password=passwordIn
    if BlobIn is None:
        myrecdblob=lastpass.Vault.readblob_local(username,password,filename=filename)
    else:
        myrecdblob=BlobIn
    timeOpen=time.time()
    timesUp=[timeOpen+timeout,timeOpen+6*timeout]
    myothervault = lastpass.Vault.open(myrecdblob, username, password)
    while len(Filter.strip())>0:
        if time.time()>timesUp[0] or time.time()>timesUp[1]:
            #inactivity or absolute timer timeout
            if time.time()>timesUp[0]:
                print "Vault inactivity timeout...Exiting"
            else:
                print "Vault absolute time timeout...Exiting"
            break 
        else:
            #reset inactivity timer
            timesUp[0]=time.time()+timeout
        p = re.compile(Filter, re.IGNORECASE)
        pp = re.compile("[a-z0-9\!\@\#\$\%\^\&\:\*\.]", re.IGNORECASE)
        print "*"*40 + " '%s'" % Filter
        white=" "*7
        revealStr="0"
        reveal=[]
        while len(revealStr.strip())>0:
			reveal=mixrange(revealStr)
			if time.time()>timesUp[0] or time.time()>timesUp[1]:
				#inactivity or absolute timer timeout
				if time.time()>timesUp[0]:
					print "Vault inactivity timeout...Exiting"
				else:
					print "Vault absolute time timeout...Exiting"
				break 
			else:
				#reset inactivity timer
				timesUp[0]=time.time()+timeout
			entry=0
			for i in myothervault.accounts:
				if p.search("%s"*7 % (i.group,i.id,i.name,i.username,i.password,i.url,i.notes)):
					entry+=1
					print "ITEM: ",entry
					if entry in reveal:
						print "Group: %s\n\tEntry: %-30s URL: '%s'\n\t User: %-29s PW: '%s' \n\tNOTES:\n%s" % (i.group,
																										   i.name,i.url,
																										   i.username,i.password,
																										   white + 
																										   white.join(i.notes.splitlines(1)))
					else:	
						print "Group: %s\n\tEntry: %-30s URL: '%s'\n\t User: %-29s PW: '%s' \n\tNOTES:\n%s" % (i.group,
																										   i.name,i.url,
																										   i.username,'*'*len(i.password),
																										   white + 
																										   white.join(pp.sub("*",i.notes).splitlines(1)))
					print "/-+-\\-+-"*10
			revealStr=raw_input("Enter item numbers to reveal, Comma-delimited(eg 1-3,7,8) [empty to quit]: ")
        Filter=raw_input("Enter Search Filter[empty to quit]: ")
    del(password)
    del(myrecdblob)
    del(myothervault)
    return True

def main(argv):
    """Parse command line inputs and execute actions."""
    helpstring =  '''localLPquery.py [options] -i <filename[LP.bin]> -u <user> 
General Options
     -a --action <xx>   select action
                             search ==> search local file [default]
                             get    ==> download a new file
     -i --filename <xx> input filename (required)
     -u --username <xx> username for download or local file (required)
Search mode options
     -f --filter <xx>   set reg-ex search filter for decoding local file
     -v --timeout <xx>  set timeout in seconds - time until vault lockout due to inactivity [600] 
Get mode options
     -t --tag           timetag downloaded file
     -o --topt <xx>     time-based one time passcode (optional)'''
    try:
        opts, args = getopt.getopt(argv,"ha:i:f:u:o:tv:",["action=","ifile=","filter=","user=","topt=","tag","timeout="])
    except getopt.GetoptError:
        print helpstring
        sys.exit(2)
    filename="LP.asc"
    filterIt='-1'
    action='search'
    timeout=600
    timetag=False
    topt='-1'
    username=None
    for opt, arg in opts:
        if opt == '-h':
             print helpstring
             sys.exit()
        elif opt in ("-i", "--ifile"):
            filename = arg
        elif opt in ("-u", "--user"):
            username = arg
        elif opt in ("-f", "--filter"):
            filterIt = arg
        elif opt in ("-a", "--action"):
            action = arg
        elif opt in ("-o", "--topt"):
            topt = arg
        elif opt in ("-t", "--tag"):
            timetag = True
        elif opt in ("-v", "--timeout"):
            timeout = int(arg)
    if action == 'search':
        while not os.path.isfile(filename):
            print "Invalid File: %s" % filename
            filename=raw_input("Enter Valid Filename: ")
        if username is None:
            print "Invalid username:"
            username=raw_input("Enter Valid username: ")            
        searchFileBlob(filename=filename,username=username,FilterIn=filterIt,timeout=timeout)
    elif action == 'get':
        getLPBlob(filename=filename,TimeTag=timetag,username=username,topt=topt)
    else: 
        print "ERROR: Unknown Action: %s\n\n%s" % (action,helpstring)
        sys.exit(2)
        
if __name__ == '__main__':
    main(sys.argv[1:])