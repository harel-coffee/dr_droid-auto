"""
buildign the method level graph 

Then we need to analyze the permissions and structures
both method level and class level

"""
import re
import copy
import sys
import pydot
import networkx as nx
#import pygraphviz as pgv

class YY_CallInOut:    
    invokeDir2 = None    # invokeDir2:{the invoking method ---> the invoked method}
    fcgnx = None        # graph for the method level 
    fcgnx_class_level = None  # graph for the class level with the weights 

    def __init__(self, methodInvokeList, classInvokelist, KE_classlist):
        self.preprocess(methodInvokeList)
        self.process_class_graph(classInvokelist, KE_classlist)
        del self.invokeDir2
    
    def __del__(self):
        self.fcgnx_class_level = None 
        self.fcgnx = None  

    def preprocess(self, methodInvokeList):
        """
            This function is to pre-process the invoke relations.
            @param methodInvokeList: the list of method ---> method
        """
        pattern=' ---> '
        self.invokeDir2 = {}
        for line in methodInvokeList:            
            parts = line.split(pattern)
            m0 = parts[0]
            m1 = parts[1]
            
            if m0 not in list(self.invokeDir2.keys()):
                self.invokeDir2[m0]=[m1]
            else:
                if m1 not in self.invokeDir2[m0]:
                   self.invokeDir2[m0].append(m1)

        # add nodes with weight (# of times call others)
        dgraph = pydot.Dot(graph_type = 'digraph')
        dgraph.set_edge_defaults(style= 'solid')
        
        # add a nx graph
        self.fcgnx = nx.DiGraph()      
        self.fcgnx.add_nodes_from((node_name) for node_name in self.invokeDir2.keys())
             
        for node_name, node_values in self.invokeDir2.iteritems():
              children = self.invokeDir2[node_name]
              self.fcgnx.add_edges_from([(node_name, child) for child in children]) 

        #print ("method level nodes: {0}, edges:{1} ".format(self.fcgnx.__len__(),self.fcgnx.size()))
        #print "method level is directed&acyclic? {0} ".format(nx.is_directed_acyclic_graph(self.fcgnx))
        """
        # add a pydot graph 
        for keys_id in self.invokeDir2.keys():
	    dnode = pydot.Node(keys_id)
	    dnode.set_style('filled')
	    dgraph.add_node(dnode)

	    #add edges
        for keys_id in self.invokeDir2.keys():
	    for values_id in self.invokeDir2[keys_id]:
                edge1 = pydot.Edge(keys_id, values_id)
	 	#edge1.set_label(lab)		
		dgraph.add_edge(edge1)
        #output
	    #dgraph.write('YY_method.dot')	
	    """
        del dgraph

    # inner class level call graph
    def process_class_graph(self, classInvokelist, KE_classlist):
        class_dic = {}
        classlist = KE_classlist
        dgraph_class = pydot.Dot(graph_type = 'digraph')
        dgraph_class.set_edge_defaults(style= 'solid', weight=0) 
        
        #build the class level 
        for keys_id in classlist:
            dnode = pydot.Node(keys_id)
            dnode.set_style('filled')
            dgraph_class.add_node(dnode)
        
        class_dic = {}
        for line in classInvokelist:
            if line in class_dic.keys():
               class_dic[line] = class_dic[line] + 1
            else :
               class_dic[line] = 1
      
        pattern=' ---> '
        for line in class_dic.keys():
            parts = line.split(pattern)
            keys_id = parts[0]
            values_id = parts[1]
            wei = class_dic[line]
            label = str(wei)  
            edge1 = pydot.Edge(keys_id, values_id, weight = wei)
            edge1.set_label(label)
            dgraph_class.add_edge(edge1)

  
        del class_dic
        del classlist
        #write
        #dgraph_class.write("YY_class.dot")
        #self.fcgnx_class_level = nx.DiGraph(nx.from_pydot(dgraph_class))
        try:
            self.fcgnx_class_level = nx.DiGraph(nx.from_pydot(dgraph_class))
            print ("Done with networkX class-graph")
        except ImportError:
            print ("you networkx may not be 1.9.*, try another import for networkx 1.11.*")
            self.fcgnx_class_level = nx.nx_pydot.from_pydot(dgraph_class)

        #print ("failed, some import issues on the networkX")
        #sys.exit(1)
        del dgraph_class
        #print "class graph succeed"
        #print ("class level nodes: {0}, edges:{1}".format(self.fcgnx_class_level.__len__(),self.fcgnx_class_level.size()))
        #print "class level is directed  & acyclic? {0} ".format(nx.is_directed_acyclic_graph(self.fcgnx_class_level)) 
	
    
	
