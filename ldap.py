import ldap3
import sys
import readline

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'
    WHITE = '\033[97m'

class L_Client(ldap3.Connection):
    
    def __init__(self,domain,uname,pwd):
        """
        Args:
            domain: Domain of the server to bind to

            uname: username

            pwd: password

        """

        super(L_Client,self).__init__(ldap3.Server(domain, get_info=ldap3.ALL),user=uname,password=pwd,authentication=ldap3.NTLM)
        self.bind()
        self.base = ""
        self.origin = ""
        self.lastCom = ""

    def setBase(self,aBase):
        """ Sets the base directory for search

        Args:
            aBase (string): A path of organizational units

        """

        self.base = aBase
        self.origin = aBase

    def getOU(self):
        """ Returns a list of all OUs in the current directory """

        self.search(self.base,'(objectClass=organizationalUnit)',search_scope=ldap3.LEVEL,attributes='distinguishedName')
        retList = list()
        for entry in self.entries:
            entry = str(entry).split(",")[0][7:]
            retList.append(entry)
        self.lastCom = "self.search(" + self.base + ",'(objectClass=organizationalUnit)',search_scope=ldap3.LEVEL,attributes='distinguishedName')"
        return sorted(retList)

    def toCommand(self):
        """ Returns the last ldap query used """
        return self.lastCom

    def getSubOU(self,OU):
        """ Returns a list of all OUs in a specified OU """
        self.search("OU="+OU+","+self.base,'(objectClass=organizationalUnit)',search_scope=ldap3.LEVEL,attributes='distinguishedName')
        retList = list()
        self.lastCom="self.search(OU="+OU+","+self.base+",'(objectClass=organizationalUnit)',search_scope=ldap3.LEVEL,attributes='distinguishedName')"
        for entry in self.entries:
            entry = str(entry).split(",")[0][7:]
            retList.append(entry)
        return sorted(retList)

    def getContents(self):
        """ Returns a list of all objects in the directory """

        self.search(self.base,'(objectClass=*)',search_scope=ldap3.LEVEL,attributes=['distinguishedName','objectClass'])
        self.lastCom="self.search("+self.base+",'(objectClass=*)',search_scope=ldap3.LEVEL,attributes=['distinguishedName','objectClass'])"
        return self.entries

    def getItems(self):
        """ Returns all non-ou items in the directory """

        self.search(self.base,'(!(objectClass=organizationalUnit))',search_scope=ldap3.LEVEL,attributes=['distinguishedName','objectClass'])
        self.lastCom="self.search("+self.base+",(!(objectClass=organizationalUnit)),search_scope=ldap3.LEVEL,attributes=['distinguishedName','objectClass'])"
        return self.entries

    def move(self,OU):
        """ Moves the base to a new subdirectory 
        
        Args:
            OU (string): The OU to move to
        """

        self.getOU()
        for a in self.entries:
            if "DN: OU=" + OU + "," in str(a):
                self.base = "OU=" + OU + "," + self.base
                return self.getOU()
        return False

    def force(self,OU):
        """ Forcibly moves base to the a new OU

        Args:
            OU (string): The OU to move to

        """

        self.base = "OU=" + OU + "," + self.base
        return self.getOU()

    def up(self):
        """ Moves the base to the previous OU """
        if self.base == self.origin:
            return False
        dirs = self.base.split(",")
        self.base = ",".join(dirs[1:])
        return self.getOU()
    
    def getMembers(self,group):
        """ Returns all members of a group contained in the origin

        Args:
            group (string): Group name

        Returns:
            A list of members that are in the group
        
        """
	print '(memberOf=cn=' + group + ',' + self.base + ')'
        self.search(self.origin,'(memberOf=cn='+ group + ','+self.base + ')',attributes=['distinguishedName','objectClass'])
        self.lastCom="self.search("+self.origin+",'(memberOf=cn="+ group +","+self.base+")',attributes=['distinguishedName','objectClass'])"
        return self.entries

    def getSpecMembers(self,group,attr):
	""" Returns specified attributes of members in a group

	Args:
	    group (string): Group name

	    attr (string): list of attributes to return
	
"""
	self.search(self.origin,'(memberof=cn='+ group +')',attributes=attr)
	self.lastCom="self.search("+self.origin+",'(memberof=cn='"+ group +"')',attributes="+str(attr)+")"
	return self.entries
	

    def searchAttributes(self,base,filter,attr,scope):
        """ Versatile search query, useful for stuff 

        Args:
            filter (string): Filter to be applied

            attributes (string): Attributes to be returned

            scope (string): scope to search

        """

        try:
            self.search(base,'(' + filter + ')',search_scope=scope,attributes=attr)
            self.lastCom = "self.search("+base+",'(" + filter + ")',search_scope=" + scope + ",attributes=" + str(attr) + ")"
        except KeyboardInterrupt:
            print "Search Interrupted"
        return self.entries
    
    def searchBase(self,filter):
        """ Returns all items in the OU that meet a certain condition

        Args:
            filter (string): LDAP Filter to apply

        Returns:
            All items that match the filter

        """

        self.search(self.base,'(' + filter + ')',search_scope=ldap3.LEVEL,attributes=ldap3.ALL_ATTRIBUTES)
        self.lastCom = "self.search("+self.base+",'(" + filter + ")',search_scope=ldap3.LEVEL,attributes=ldap3.ALL_ATTRIBUTES)"
        return self.entries

    def searchSmall(self,filter):
        """ Returns distinguished name of all items in the OU that meet a certain condition

        Args:
            filter (string): LDAP Filter to apply

        Returns:
            All items that match the filter
        
        """

        self.search(self.base,'(' + filter + ')',search_scope=ldap3.LEVEL,attributes='distinguishedName')
        self.lastCom = "self.search("+self.base+",'(" + filter + ")',search_scope=ldap3.LEVEL,attributes='distinguishedName')"
        return self.entries

    def searchSub(self,filter):
        """ Searches the subtree of the base OU with a filter

        Args:
            filter (string): LDAP Filter to apply

        Returns:
            All items that match the filter

        """

        self.search(self.base,'(' + filter + ')',search_scope=ldap3.SUBTREE,attributes='distinguishedName')
        self.lastCom = "self.search("+self.base+",'( "+ filter +" )',search_scope=ldap3.SUBTREE,attributes='distinguishedName')"
        return self.entries

    def back(self):
        """ Returns the base ou to the origin """
        self.base = self.origin
        return self.getOU()

    def searchOrigin(self,filter):
        """ Applies a search filter from the origin
        
        Args:
            filter (string): LDAP Filter to apply

        Returns:
            All items that match the filter
        
        """

        self.search(self.origin,'(' + filter + ')',search_scope=ldap3.SUBTREE,attributes='distinguishedName')
        self.lastCom = "self.search("+self.origin+",'("+ filter +")',search_scope=ldap3.SUBTREE,attributes='distinguishedName')"
        return self.entries


#Main loop of the program, functions similar to a terminal
def loop(l):
    com = " "
    temp = list()
    print bcolors.WHITE + str(l.getOU())
    while not com[0] == "quit":
        com = raw_input(bcolors.BOLD + bcolors.OKGREEN + "[" + l.base + "] >>> " + bcolors.ENDC + bcolors.WHITE).split(" ")
        print ""
        op = com[0]
        #Pretty much follows formatting:
        #if (optional args):
        #else
        #Move command, used for moving between OUs
        args = 1
        if op == "move":
            if len(com) == 1:
                continue
            if com[1] == "..":
                print l.up()
            elif com[1] == "~":
                print l.back()
            elif len(com) > 1:
                print l.move(" ".join(com[1:]))
            dirs = len(l.entries)
            l.getContents()
            rest = len(l.entries)
            print str(rest - dirs) + " others"
        #Force command, used to forcibly change OU (useful for hidden OUs)
        elif op == "force":
            if len(com) == 1:
                continue
            if com[1] == "..":
                print l.up()
            elif com[1] == "~":
                print l.back()
            elif len(com) > 1:
                print l.force(" ".join(com[1:]))
            dirs = len(l.entries)
            l.getContents()
            rest = len(l.entries)
            print str(rest - dirs) + " others"
        #Lists all OUs in the current OU
        elif op == "dir":
            if len(com) == 1:
                print l.getOU()
            #Lists OUs in a specified OU
            elif len(com) > 1:
                print l.getSubOU(" ".join(com[1:]))
        #Lists all items in the OU
        elif op == "get":
            if len(com) == 1:
                for item in l.getContents():
                    print item
            #Gets all non-OU items in the OU
            elif com[1] == "-i":
                for item in l.getItems():
                    print item
        #Searches for items that match a given filter
        elif op == "search":
            try: 
                #Sets the base parameters: The current base, current level, and only returns name
                base = l.base
                scope = ldap3.SUBTREE
                attrib = 'distinguishedName'
                args = 1
                #Searches from the subtree of the origin
                if "-o" in com:
                    base = l.origin
                    scope = ldap3.SUBTREE
                    args+=1
                #Searches the current level
                if "-l" in com:
                    scope = ldap3.LEVEL
                    args+=1
                #Returns all attributes of items that match the filter
                if "-a" in com:
                    attrib = ldap3.ALL_ATTRIBUTES
                    args+=1
                #Returns specific attributes of matched items
                if "-p" in com:
                    args+=2
                    attrib = com[com.index('-p')+1].split(",")
                #Performs the search
                if len(com) > 1:
                    for item in l.searchAttributes(base," ".join(com[args:]),attrib,scope):
                        print item
                print str(len(l.entries)) + " result(s)"
            except Exception, e:
                print e.message
        #Gets members of a group, no cn= needed (actually, only works without it)
        elif op == "members":
            attrib = ['distinguishedName',]
            if "-p" in com:
                args+=2
                attrib = com[com.index('-p')+1].split(",")
            if len(com) > 1:
                for item in l.getSpecMembers(" ".join(com[args:]),attrib):
                    print item
                print str(len(l.entries)) + " result(s)"
        #Saves the most recent output in a list
        elif op == "save":
            if len(com) == 1:
                temp.append(l.entries)
                print "Saved at " + str(len(temp) - 1)
            elif len(com) == 2:
                try:
                    ind = int(com[1])
                    if len(temp) >= ind:
                        temp[ind] = l.entries
                        print "Saved at " + com[1]
                    else:
                        print "No data at index " + com[1]
                except Exception, e:
                    print e.message
        #Prints the output saved at a given index
        elif op == "load":
            try:
                if len(com) > 1:
                    if len(temp) > int(com[1]):
                        for a in temp[int(com[1])]:
                            print a
                    else:
                        print "No data at index " + com[1]
                else:
                    print "Usage: load <#>"
            except Exception, e:
                print e.message
        #Prints the last ldap query used
        elif op == "query":
            print l.toCommand()
        elif op == "help":
            with open("help.txt") as f:
                print f.read()
        elif com[0] != "quit":
            print "Unrecognized Command"
    print bcolors.ENDC

if __name__ == "__main__":  
    import argparse

    parser = argparse.ArgumentParser()
    
    parser.add_argument('-d', dest = 'dc', required = True, metavar = 'DC', help = 'LDAP domain controller')
    parser.add_argument('-u', dest = 'uname', required = True, metavar = 'UNAME', help = 'LDAP user name')
    
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-p', dest = 'pwd', metavar = 'PWD', help = 'LDAP password')  
    group.add_argument('-f', dest = 'file', metavar = 'FILE', help = "Password containing ldap file")
    
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            pwd = f.readline().strip()
    else:
        pwd = args.pwd

    l = L_Client(args.dc, args.uname, pwd)
    
    #Need to set this
    l.setBase('dc=YOUR,dc=BASE,dc=HERE')
    if l.base == 'dc=YOUR,dc=BASE,dc=HERE':
        print "Domain Components not set"
        exit()
    
    loop(l)
