import sys

if sys.path[0] == "":
	sys.path.append(sys.path[1]+"/androguard/")
	PATH_INSTALL = sys.path[1]+"/androguard"
else:
	sys.path.append(sys.path[0]+"/androguard/")
	PATH_INSTALL = sys.path[0]+"/androguard"

sys.path.append(PATH_INSTALL + "./")
sys.path.append(PATH_INSTALL + "/core")
sys.path.append(PATH_INSTALL + "/core/bytecodes")
sys.path.append(PATH_INSTALL + "/core/predicates")
sys.path.append(PATH_INSTALL + "/core/vm")
sys.path.append(PATH_INSTALL + "/core/wm")
sys.path.append(PATH_INSTALL + "/core/protection")
sys.path.append(PATH_INSTALL + "/classification")
 
#import androguard, analysis, androlyze
import bytecode
from dvm import *


class CLASS:

    apk = None
    vm = None
    vmx = None
    
    def __init__(self, apk, vm, vmx):
        self.apk = apk
        self.vm = vm
        self.vmx = vmx
    
    def get_class(self):
        return self.vm.get_classes()
        
    def get_classname(self, classes):
        return classes.get_name()
    
    def get_methods(self, classes):
        return classes.get_methods()
    
    def get_methodname(self, method):
        return method.get_name()
        
    def get_code(self, method):
        return method._code.show()
        
    def get_classlist(self):
        return self.vm.get_classes_names()
    
    def get_methods_class(self, classes):
        return self.vm.get_methods_class(classes)
    
    def get_maxdepth(self):
        classesnames = self.vm.get_classes_names()
        maxdepth = 0
        for i in classesnames:
            l = len(i.split("/"))
            if l > maxdepth:
                maxdepth = l
                
        return maxdepth


    #get where a permission is used
    def get_permission(self):
        pathDict = {}
        perms_access = self.vmx.tainted_packages.get_permissions([])
        for perm in perms_access:
            pathDict[perm] = self.show_path(perms_access[perm])
        
        return pathDict
  
    
    def show_path(self, paths):
        accessPathList = []
        for path in paths:
            if isinstance(path,analysis.PathP):
                if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL:
                    accessPath = ("%s %s %s (@%s-0x%x)  --->  %s %s %s") % (path.get_method().get_class_name(), path.get_method().get_name(), \
                                                                     path.get_method().get_descriptor(), path.get_bb().get_name(), path.get_bb().start + path.get_idx(), \
                                                                     path.get_class_name(), path.get_name(), path.get_descriptor())
                    
                    accessPathList.append(accessPath)
            
        return accessPathList
        
        
    
    # All Invoke Methods
    # build two different level of graphs
    def get_methodInvoke(self):

        allMethods = self.vm.get_methods()
        allClasses = self.get_classlist()
        
        The_methodinvokelist = None
        The_methodinvokelist = []
        The_intentmethodinvoke = None
        The_intentmethodinvoke = []

        The_classinvokelist = []
        
        ENTRY_POINT= ['onCreate', 'onReceive']
        dic_class_method = {}  

        # we do not consider google play serive and support library
        support_str ="android/support/v"
        gms_string = "google/android/gms" 
        
        remove_list = []
        for item in allClasses:
            if str(support_str) in str(item) or str(gms_string) in str(item):
               remove_list.append(item)               

        for item in remove_list:
            allClasses.remove(item)       
         
         
        #if len(allClasses)> 1000:
        #   print (" LONG ") 
        #   raise RuntimeError 
                                     
        for class_n in allClasses:
            if '$' in class_n:
                t = class_n.split("$")
                parent_class = ""
                for i in range(0,len(t)-1):
                    parent_class = parent_class + str(t[i]) + "$"
                parent_class = parent_class[:-1] + ';'
                              
                if parent_class in allClasses and '/R$' not in class_n: #remove R classes
                   #print (class_n, parent_class) 
                   The_classinvokelist.append(class_n + " ---> " + parent_class)
  
        for m in allMethods:
          
            invokingMethod = m.get_class_name() + " " + m.get_descriptor() +"," + m.get_name()
            invokingMethod1 = m.get_class_name() + " " + m.get_name()
  
            class_n = str(m.get_class_name())
            method_n = str(m.get_name())

            if str(support_str) in str(class_n) or str(gms_string) in str(class_n):
               continue

            if '$' not in class_n:            
               if class_n not in dic_class_method.keys():
                  dic_class_method[class_n] = []   
                  dic_class_method[class_n].append(method_n)
               else:
                  dic_class_method[class_n].append(method_n)               

            if '$' in class_n: 
                if not method_n in "<init>":
                   try:
                      init_method = class_n + " " + "<init>"
                      invoke1 = init_method + " ---> " +  class_n + " " +  method_n
                      #The_intentmethodinvoke.append(invoke1)
                      
                   except:
                      print (invokingMethod1)

            flag = 0
            flag_intent = 0
            temp_class = None
            temp_class = []           
            code =  m.get_code()
            if code == None:
                continue
            else:
                bc = code.get_bc()
                idx = 0
                lineNum = 1
                for i in bc.get():
                    
                    #line = i.show()
                    line ="%s %s" % (i.get_name(), i.get_output())
                    #print line 
                    #raw_input()
                    # call triggering 
                    if line.find("invoke-") >= 0:
                       
                       try: 
                           index = line.index("L")
                           method = str(line[index:])
                           method2 = method.split("->")                        

                           # set the class                       
                           className = method2[0]                         
                           methodName = method2[1].split("(")[0]
                        
                           # set the descriptor name 
                           if className in allClasses :                       
                              invokedMethod1 = className + " " + methodName
                              The_methodinvokelist.append(invokingMethod1 + " ---> " + invokedMethod1)
                              The_classinvokelist.append(m.get_class_name() + " ---> " + className)
                            
                       except:
                           pass
                           #print ("FAULT Invoke:  {}".format(line))
                    
                    # data dependence from
                    if (line.find("sget") >=0) or (line.find("iget") >=0) :
                       try :
                           method = line.split(" ")[-1]
                           class_name = method.split("->")[0]
                           if class_name in allClasses :
                              The_classinvokelist.append(m.get_class_name() + " ---> " + class_name)
  
                       except:
                           print (line)
                    
                    # data dependece to
                    if (line.find("sput") >=0) or (line.find("iput") >=0) :
                       try :
                           method = line.split(" ")[-1]
                           class_name = method.split("->")[0]
                           if class_name in allClasses :
                              The_classinvokelist.append(m.get_class_name() + " ---> " + class_name)
  
                       except:
                           print (line)  

                    # IPC involved  (genrally speaking const-calss can be regarded as a weak data dependnece)          
                    if line.find("const-class")  >= 0:

                       flag = 1
                       try: 
                           index = line.index("L")
                           class_name = str(line[index:])
                           #if class_name in allClasses :
                           #   The_classinvokelist.append(m.get_class_name() + " ---> " + class_name) #data
                       except:
                           pass
                           #print (line) 

                       if class_name in allClasses :
                           temp_class.append(class_name)

                    if line.find("new-instance") >= 0 and line.find("Landroid/content/Intent;") >=0:
                       flag_intent = 1                     

                    if line.find("startActivity") >=0 or line.find("startService") >=0 or line.find("sendBroadcast")>=0 and (flag>0) and (flag_intent>0):
                       
                       try:
                           #print (line)
                           if len(temp_class) > 0:
                              n =len(temp_class) 
                              class_name = temp_class[n-1]
                              temp_class.pop()

                           if class_name in allClasses :
                              invokedMethod2 = class_name + " " + "onCreate"
                              The_intentmethodinvoke.append(invokingMethod1 + " ---> " + invokedMethod2)
                              The_classinvokelist.append(m.get_class_name() + " ---> " + class_name) #ICC
                              flag_intent = 0                       
                       except:
                           print (line)

                    if line.find("new-instance") >= 0:
                       try:
                           index = line.index("L")
                           class_name = str(line[index:])
                           if class_name in allClasses :
                              The_classinvokelist.append(m.get_class_name() + " ---> " + class_name)
  
                              invokedMethod2 = class_name + " " + "<init>"
                              #The_intentmethodinvoke.append(invokingMethod1 + " ---> " + invokedMethod2)
                       except:
                              print (line)
                           
   
                    lineNum += 1
                    idx += i.get_length() 
                     

        for i in dic_class_method.keys():
            flag = False
            entry_p = None
            for j in dic_class_method[i]:
               for k in ENTRY_POINT:
                   if k == j:
                      flag =True
                      #print(k,j)
                      entry_p = j
                      break
               if flag:
                  break
            if flag:
               entry_m = str(i + " " + entry_p)
               for j in dic_class_method[i]:
                   if not j==entry_p: 
                      mm = str(i + " " + j)
                      The_intentmethodinvoke.append(entry_m + " ---> " + mm)
                      #print (entry_m + " ---> " + mm)


        total_list = The_methodinvokelist +  The_intentmethodinvoke

        return total_list, The_classinvokelist, allClasses
