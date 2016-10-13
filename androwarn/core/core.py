#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

# Global imports

##
# ke find some bugs in this codes and modified 
##

import re, logging

# Androguard imports
from androguard.core.analysis.analysis import *

# Androwarn modules import
from androwarn.constants.api_constants import *

# Constants 
ERROR_VALUE_NOT_FOUND = 'N/A'
ERROR_CONSTANT_NAME_NOT_FOUND = 'N/A'


INIT = 'initial'

CONST_STRING = 'const-string'
CONST = 'const'
MOVE = 'move'
NEW_INSTANCE = 'new-instance'
IGET = 'iget'
MOVE_RESULT = 'move-result'
APUT = 'aput'
SGET = 'sget'
AGET = 'aget'
INVOKE = 'invoke'
INVOKE_NO_REGISTER = 'invoke-no-register'
INVOKE_2_REGISTER = 'invoke-2-registers'
INVOKE_MORE_REGISTER = 'invoke-more-register'


# Logguer
log = logging.getLogger('log')

# Instruction matcher
def match_current_instruction(current_instruction, registers_found) :
	"""
		@param current_instruction : the current instruction to be analyzed
		@param registers_found : a dictionary of registers recovered so far
	
		@rtype : the instruction name from the constants above, the local register number and its value, an updated version of the registers_found
	"""
	p_const 				= re.compile('^const(?:\/4|\/16|\/high16|-wide(?:\/16|\/32)|-wide\/high16|)? v([0-9]+), \#\+?(-?[0-9]+(?:\.[0-9]+)?)$')
	p_const_string			= re.compile("^const-string(?:||-jumbo) v([0-9]+), '(.*)'$")
	p_move					= re.compile('^move(?:|\/from16|-wide(?:\/from16|\/16)|-object(?:|\/from16|\/16))? v([0-9]+), (v[0-9]+)$')
	p_move_result			= re.compile('^move(?:-result(?:|-wide|-object)|-exception)? v([0-9]+)$')
	p_aput					= re.compile('^aput(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), v([0-9]+), v([0-9]+)$')
	p_invoke 				= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), (L(?:.*);->.*)$')
	p_invoke_2_registers 	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), v([0-9]+), (L(?:.*);->.*)$')
        
        #ke added  
        p_invoke_more_registers 	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), v([0-9]+), v([0-9]+)*, (L(?:.*);->.*)$')
           
	p_invoke_no_register	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) (L(?:.*);->.*)$')
	p_new_instance 			= re.compile('^new-instance v([0-9]+), (L(?:.*);)$')
	
        # ke added 
        p_aget                          = re.compile("^aget(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), v([0-9]+), v([0-9]+)$")
        p_sget                          = re.compile("^sget(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), (L(?:.*);->.*)$")     
	p_iget                          = re.compile("^iget(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), v([0-9]+), (L(?:.*);->.*)$") 
	# String concat
	current_instruction = "%s %s" % (current_instruction.get_name(), current_instruction.get_output())

	instruction_name = ''
	local_register_number = -1
	local_register_value = -1
	para_dependent = -1

        ######### IGET
	if p_iget.match(current_instruction) :
		
		instruction_name = IGET
                """
                print ("IGET YYYYYYYYYYYYYYYYYY")
                print (current_instruction)
             	print (p_iget.match(current_instruction).groups())
                raw_input()
                """
                temp = p_iget.match(current_instruction).groups()
		register_number1 = temp[0]
                register_number2 = temp[1]
		register_value =   temp[2]
                #register_value_local = register_value

		if not(register_number1 in registers_found) or (registers_found[register_number1]=='') :
			registers_found[register_number1] = register_value
		
                if not(register_number2 in registers_found):
                        registers_found[register_number2] = '' 
	
                para_dependent =  register_number2                
		local_register_number = register_number1
		local_register_value = register_value

        ########### AGET
        if p_aget.match(current_instruction) :
		#print p_const_string.match(current_instruction).groups()
		
		instruction_name = AGET
                
		register_number1 = p_aget.match(current_instruction).groups()[0]
                register_number2 = p_aget.match(current_instruction).groups()[1]
		register_number3 = p_aget.match(current_instruction).groups()[2]
                
		if not(register_number1 in registers_found):
		       registers_found[register_number1] = ''
		
		
                if not(register_number2 in registers_found):
                       registers_found[register_number2] = '' 

	        if not(register_number1 in registers_found):
		       registers_found[register_number1] = ''
		 
                para_dependent =  register_number2
		local_register_number = register_number1
		local_register_value = local_register_value 
 
        ########### SGET
        if p_sget.match(current_instruction) :
		#print p_const_string.match(current_instruction).groups()
		#print "OK"
		instruction_name = SGET
		
		register_number = p_sget.match(current_instruction).groups()[0]
		register_value = p_sget.match(current_instruction).groups()[1]

		if not(register_number in registers_found) or registers_found[register_number]=='':
			registers_found[register_number] = register_value
		else :
                        pass
			
		local_register_number = register_number
		local_register_value = register_value

        ############# CONST_STRING
	if p_const_string.match(current_instruction) :
		#print p_const_string.match(current_instruction).groups()
		
		instruction_name = CONST_STRING
		
		register_number = p_const_string.match(current_instruction).groups()[0]
		register_value = p_const_string.match(current_instruction).groups()[1]
		
		if not(register_number in registers_found) or registers_found[register_number]=='':
			registers_found[register_number] = register_value
		else :
                        pass
                        """
			old_string = registers_found[register_number]
			#new_string = "%s %s" % (str(register_value), str(old_string))
			new_string = register_value
                        registers_found[register_number] = new_string
		        """
		local_register_number = register_number
		local_register_value = register_value

        ########## CONST
	if p_const.match(current_instruction) :
		#print p_const.match(current_instruction).groups()
		
		instruction_name = CONST
		
		register_number = p_const.match(current_instruction).groups()[0]
		register_value = p_const.match(current_instruction).groups()[1]
		
		if not(register_number in registers_found) or registers_found[register_number]=='':
			registers_found[register_number] = register_value
		
		local_register_number = register_number
		local_register_value = register_value

        ########### MOV
	if p_move.match(current_instruction) :
		#print p_move.match(current_instruction).groups()
		
		instruction_name = MOVE

                register_number = p_move.match(current_instruction).groups()[0]
		register_value = p_move.match(current_instruction).groups()[1]
		
                pattern = re.compile('^v([0-9]+)$');
                register_number2 = pattern.match(register_value).groups()[0]

		if not(register_number in registers_found) :
			registers_found[register_number] = register_value				
		
                if not(register_number2 in registers_found) :
			registers_found[register_number2] = ''
                
                para_dependent =  register_number2    
		local_register_number = register_number
		local_register_value = register_value

        ############# MOVE_RESULT
	if p_move_result.match(current_instruction) :
		#print p_move_result.match(current_instruction).groups()
		
		instruction_name = MOVE_RESULT
		
		register_number = p_move_result.match(current_instruction).groups()[0]
		register_value = ''
		
		if not(register_number in registers_found) :
			registers_found[register_number] = register_value		
		
		local_register_number = register_number
		local_register_value = register_value	
			
        ############ INVOKE
	if p_invoke.match(current_instruction) :
		#print p_invoke.match(current_instruction).groups()
		
		instruction_name = INVOKE
		
		register_number = p_invoke.match(current_instruction).groups()[0]
		register_value = p_invoke.match(current_instruction).groups()[1]
		
                #ke test
		#if not(register_number in registers_found) :
		#       registers_found[register_number] = register_value		
		
		local_register_number = register_number
		local_register_value = register_value		
	
        ######## INVOKE  NO REGISTERS
	if p_invoke_no_register.match(current_instruction) :
		#print p_invoke.match(current_instruction).groups()
		
		instruction_name = INVOKE_NO_REGISTER
		
		register_number = ''
		register_value = p_invoke_no_register.match(current_instruction).groups()[0]
		
		local_register_number = register_number
		local_register_value = register_value

        ############# INVOKE MORE REGISTERS
        if p_invoke_more_registers.match(current_instruction) :	
                
                instruction_name = INVOKE_MORE_REGISTER
		
                temp = p_invoke_more_registers.match(current_instruction).groups()  
		register_number = temp[:len(temp)-2]
		register_value = temp[len(temp)-1]
		
		local_register_number = register_number
		local_register_value = register_value           

        ####### INOVKE 2 REGISTERS
	if p_invoke_2_registers.match(current_instruction) :
		#print p_invoke.match(current_instruction).groups()
		
		instruction_name = INVOKE_2_REGISTER
		
                register_number = [] 
		register_number1 = p_invoke_2_registers.match(current_instruction).groups()[0]
                register_number2 = p_invoke_2_registers.match(current_instruction).groups()[1]
                register_number.append(register_number1)
                register_number.append(register_number2)

		register_value = p_invoke_2_registers.match(current_instruction).groups()[2]
		
		local_register_number = register_number
		local_register_value = register_value		
		
        ####### NEW INSTANCE
	if p_new_instance.match(current_instruction) :
		#print p_new_instance.match(current_instruction).groups()
		
		instruction_name = NEW_INSTANCE
		
		register_number = p_new_instance.match(current_instruction).groups()[0]
		register_value = p_new_instance.match(current_instruction).groups()[1]
		
		if not(register_number in registers_found) :
			registers_found[register_number] = register_value		
		
		local_register_number = register_number
		local_register_value = register_value
	
        ####### APUT MATCH
	if p_aput.match(current_instruction) :
		#print p_aput.match(current_instruction).groups()
		
		instruction_name = APUT
		
		register_object_reference = p_aput.match(current_instruction).groups()[0]
		register_array_reference = p_aput.match(current_instruction).groups()[1]
		register_element_index = p_aput.match(current_instruction).groups()[2]

		local_register_number = register_object_reference 
		local_register_value =  register_array_reference
	
        #ke added	
	#print ("%s %s %s " %(instruction_name, local_register_number, local_register_value))
        #print ("YY %s \n"  %registers_found )

	return instruction_name, local_register_number, local_register_value, registers_found, para_dependent	

# Backtrace registers #
def find_call_index_in_code_list(index_to_find, instruction_list):
	"""
	@param index_to_find : index of the method call
	@param code_list : instruction list of the parent method called
	
	@rtype : the index of the method call in the instruction listing
	"""	
	idx = 0
	for i in instruction_list :
		if index_to_find <= idx :
			#print "[+] code offset found at the index " + str(instruction_list.index(i))
			return instruction_list.index(i)
		else :
			idx += i.get_length()
	
	# in case of failure, return an inconsistent value
	return ERROR_INDEX_NOT_FOUND


#ke added this part 
def parameters_dependence_find_one_by_one(x, method, index_to_find, index):
    
    code = method.get_code()
    #code.show()
	
    bc = code.get_bc()
    instruction_list = [ i for i in bc.get_instructions() ]
	
 
    found_index = find_call_index_in_code_list(index_to_find, instruction_list)
    trigger_option = False  
    data_dependent = []   
 
    if (found_index < 0) :
	log.error("The call index in the code list can not be found")
	return 0
		
    else :
        registers_final = {}
		
        # Initialize the harvesting dictionary
	registers_found = {}
		
	# List the register indexes related to the method call
	relevant_registers = relevant_registers_for_the_method(instruction_list[found_index])
        rr = []
   
        # to determine whether it is the initial case
        if isinstance(index, list):  
           for i in index:
               try:        
                  rr.append(relevant_registers[i])
               except:
                  print (relevant_registers)
                  print (index)
                  # how to distinguish calling with less parameters?  

        if isinstance(index, str):
           if index == INIT:
              rr = relevant_registers
              
        #print (relevant_registers )
        #print (rr)
	i = int(found_index) - 1 # start index

        for temp in rr: 
            #print (temp) 
            dependence_flag = True
            dependence_para = []
            dependence_para.append(temp)
            all_method = [ ] 
            i = int(found_index) - 1
            while (dependence_flag  and (i >= 0)) :
                  current_instruction = instruction_list[i]
                  instruction_name, local_register_number, local_register_value, registers_found, para_dependent =  match_current_instruction(current_instruction, registers_found) 
                  #current_instruction
                  #print (dependence_para )
                  #print (all_method )
                  if ((cmp(instruction_name, MOVE_RESULT) == 0) and (str(local_register_number) in dependence_para) ):
                         
                                #print ("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY") 
				try:
					
					past_instruction = instruction_list[i-1]
					p_instruction_name, p_local_register_number, p_local_register_value, registers_found, para_dependent =  match_current_instruction(past_instruction, registers_found)
                                        #print ("{} {} {}".format(p_instruction_name, p_local_register_number, p_local_register_value))
                                        if (cmp(p_instruction_name, INVOKE_NO_REGISTER) == 0):
					    dependence_para.remove(local_register_number)
                                            all_method.append(p_local_register_value)

                                        if (cmp(p_instruction_name, INVOKE) == 0):
                                            dependence_para.remove(local_register_number)
				            dependence_para = dependence_para + list(p_local_register_number)
                                            all_method.append(p_local_register_value)
                                        
                                        if (cmp(p_instruction_name, INVOKE_2_REGISTER) == 0) or (cmp(p_instruction_name, INVOKE_MORE_REGISTER) == 0):
                                            dependence_para.remove(local_register_number)
				            dependence_para = dependence_para + p_local_register_number
                                            all_method.append(p_local_register_value)          
                                         
				except:
					log.debug("'%s' does not exist anymore in the relevant_registers list" % local_register_value)
                  
                  if ( cmp(instruction_name, IGET) == 0) or (cmp(instruction_name, AGET) == 0)  :
                      if str(local_register_number) in dependence_para:
                         all_method.append(local_register_value)
                         dependence_para.remove(str(local_register_number))
                         dependence_para.append(str(para_dependent))   
                         
                  if ( cmp(instruction_name, MOVE) == 0)   :
                     if str(local_register_number) in dependence_para:
                         dependence_para.remove(str(local_register_number))
                         dependence_para.append(str(para_dependent))   

                  if  (cmp(instruction_name, CONST) == 0) or (cmp(instruction_name, CONST_STRING) == 0) or (cmp(instruction_name, SGET) == 0) or (cmp(instruction_name, NEW_INSTANCE) == 0) or (cmp(instruction_name, SGET) == 0) :
                      if str(local_register_number) in dependence_para:
                         all_method.append(local_register_value)
                         dependence_para.remove(str(local_register_number))
               
                  if (len( dependence_para) < 1 ):
                         dependence_flag = False           
                  i=i-1
            
            trigger_string =  "Landroid/widget/EditText;->getText()"  
            if dependence_flag:
               for i in dependence_para: 
                   if i not in data_dependent:
                      data_dependent.append(i) 

            for i in all_method:
              try :
 
                if trigger_string in str(i):
                   #print ("Para {} has been triggered by getText \n{}".format(temp,all_method))
                   #print ("Data trigger found!")

                   trigger_option = True   
                   return trigger_option, data_dependent 

              except KeyError:
                   print (all_method)  
            """  
            print ("\n\n\n\n HWWWWWWWWWWWWWWWW")
            print ( "{} {}".format(temp,type(temp)) )
            print ( dependence_para )
            print ( all_method )
            raw_input()            
        #   """
        return trigger_option, data_dependent


#register is a dictionary
def check_and_update(registers_find):

    pattern = re.compile('^v([0-9]+)$');
    keys = [ i for i in registers_find.keys()]

    for i in keys:  
        if pattern.match(registers_find[i]):            
           j = pattern.match(registers_find[i]).groups()[0]
           if j in keys:
              if not registers_find[j] == '' :
                 registers_find[i] = registers_find[j]
    return registers_find   

def backtrace_registers_before_call(x, method, index_to_find) :
	"""
		@param x : a VMAnalysis instance
		@param method : a regexp for the method (the package)
		@param index_to_find : index of the matching method
	
		@rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
	"""	
	#registers = {}
	#print ("%s %s" % (method.get_class_name(), method.get_name()))
        #raw_input()
	code = method.get_code()
	#code.show()
	
	bc = code.get_bc()
	instruction_list = [ i for i in bc.get_instructions() ]
	
 
	found_index = find_call_index_in_code_list(index_to_find, instruction_list)
	
	if (found_index < 0) :
		log.error("The call index in the code list can not be found")
		return 0
		
	else :
		# Initialize the returned list of dictionaries
		registers_final = {}
		
		# Initialize the harvesting dictionary
		registers_found = {}
		
		# List the register indexes related to the method call
		relevant_registers = relevant_registers_for_the_method(instruction_list[found_index])

		i = int(found_index) - 1 # start index

		while ((all_relevant_registers_filled(registers_found,relevant_registers) != True) and (i >= 0)) :
			current_instruction = instruction_list[i]

			instruction_name, local_register_number, local_register_value, registers_found,para_dependent =  match_current_instruction(current_instruction, registers_found)

                         
                        registers_found = check_and_update(registers_found)
                        """
			if cmp(instruction_name, APUT) == 0 or cmp(instruction_name, SGET) == 0:
				try :
					list_index_to_be_changed = relevant_registers.index(int(local_register_value))
					#print "index_to_be_changed %s" % list_index_to_be_changed
					del(relevant_registers[int(local_register_value)]) 
					relevant_registers.insert(list_index_to_be_changed, local_register_number)
					log.debug("New relevant_registers %s" % relevant_registers)
				except :
					log.debug("'%s' does not exist anymore in the relevant_registers list" % local_register_value)
			                                
                        """
			if (cmp(instruction_name, MOVE_RESULT) == 0) and (local_register_number in relevant_registers):
				try:
					#past_instruction = instruction_list[i-1].show_buff(0)
					#print past_instruction
					past_instruction = instruction_list[i-1]
					p_instruction_name, p_local_register_number, p_local_register_value, registers_found, para_dependent =  match_current_instruction(past_instruction, registers_found)

					#print ("Past %s %s %s \n" %(p_instruction_name, p_local_register_number, p_local_register_value))
					# ke added 
                                        
                                        if registers_found[local_register_number] == '':
                                           registers_found[local_register_number] = p_local_register_value

                                        """
					if cmp(p_instruction_name, INVOKE_NO_REGISTER) == 0 :
						registers_found[local_register_number] = p_local_register_value
					
					else:
						list_index_to_be_changed = relevant_registers.index(str(local_register_number))
						del(relevant_registers[int(list_index_to_be_changed)])
						relevant_registers.insert(list_index_to_be_changed, p_local_register_number)
					"""
					log.debug("New relevant_registers %s" % relevant_registers)
				
				except:
					log.debug("'%s' does not exist anymore in the relevant_registers list" % local_register_value)

			i = i - 1
		
		#log.info('Registers found during the analysis %s' % registers_found)
			
			
		
		final_answer = all_relevant_registers_filled(registers_found,relevant_registers)
		log.debug("Are all relevant registers filled ? %s" % str(final_answer))
		
		for i in relevant_registers :			
			try:
				register_number	= i
				#print register_number
				
				register_value 	= registers_found[i]
				#print register_value
				
				#temp_dict = { register_number : register_value }
				registers_final[i] = register_value
			
			except KeyError:
				registers_final = {}
                                print ("Except!!!!!!!!!!!!!!!!!!") 
				log.debug("KeyError exception : The value of the register # %s could not be found for the relevant registers %s" % (register_number, relevant_registers))
				break
		"""		
		print (registers_found)
		print (registers_final)
                print ("relevant {}".format(relevant_registers)) 
                raw_input()
		"""

                return registers_final

		
def extract_register_index_out_splitted_values(registers_raw_list_splitted) :
	"""
		@param : registers_raw_list_splitted : a list of registers still containing the 'v' prefix [' v1 ', ' v2 ' ...]
	
		@rtype : an ordered list of register indexes ['1', '2' ...]
	"""		
	relevant_registers = []
	
	# Trim the values
	registers_raw_list_splitted[:] = (value.strip() for value in registers_raw_list_splitted if len(value) > 0)
	
	for value in registers_raw_list_splitted :
		
		# Remove that 'v'
		p_register_index_out_of_split = re.compile('^v([0-9]+)$')
		
		if p_register_index_out_of_split.match(value) :
			#print p_register_index_out_of_split.match(value).groups()
			register_index = p_register_index_out_of_split.match(value).groups()[0]
			
			relevant_registers.append(register_index)
		
		else :
			relevant_registers.append('N/A')
	
	return relevant_registers


def relevant_registers_for_the_method(instruction) :
	"""
		@param method : a method instance
		@param index_to_find : index of the matching method
	
		@rtype : an ordered list of register indexes related to that method call
	"""	
	relevant_registers = []
	
	current_instruction_name = instruction.get_name()
	current_instruction = instruction.show_buff(0)
	
	
	p_invoke_name 		= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)$')
	p_invoke_range_name	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)(?:\/range)$')

	if p_invoke_name.match(current_instruction_name) :
		
		p_invoke_registers = re.compile('(v[0-9]+),')
		
		if p_invoke_registers.findall(current_instruction) :
			registers_raw_list_splitted = p_invoke_registers.findall(current_instruction)
			relevant_registers = extract_register_index_out_splitted_values(registers_raw_list_splitted)
	
	
	if p_invoke_range_name.match(current_instruction_name) :
		# We're facing implicit an implicit range declaration, for instance "invoke v19..v20"
		p_invoke_registers_range = re.compile('^v([0-9]+) ... v([0-9]+), L.*$')
		
		if p_invoke_registers_range.match(current_instruction) :
			register_start_number = p_invoke_registers_range.match(current_instruction).groups()[0]
			register_end_number = p_invoke_registers_range.match(current_instruction).groups()[1]
			
			if int(register_start_number) > int(register_end_number) :
				log.error("invoke-kind/range incoherent: # of the start register is lower than the end one")
			else :
				relevant_registers = [ str(i) for i in xrange(int(register_start_number), int(register_end_number)+1)]
				# +1 because range does not provide the higher boundary value
                                # ke modified the codes here
		
	return relevant_registers

def all_relevant_registers_filled(registers, relevant_registers) :
	"""
	@param registers : a dictionary of each register content { 'register #': 'value' }
	@param relevant_registers : an ordered list of register indexes related to that method call
	
	@rtype : True if all the relevant_registers are filled, False if not 
	"""	
	answer = True
        pattern = re.compile('^v([0-9]+)$');
	for i in relevant_registers :
		# assert a False answer for null registers from the "move-result" instruction
		if not(i in registers) or (i in registers and len(str(registers[i])) < 1) :
			answer = False
                if i in registers: 
                   if pattern.match(registers[i]):
                        #raw_input()
                        #print (registers[i])  
                        answer = False
	return answer


def get_register_value(index, registers) :
	"""
		@param index : integer value of the index
		@param registers : an ordered list of register indexes related to that method call
	
		@rtype : a value casted in string
	"""
	# Index - 1, list starts at index 0
	if index <= len(registers) :
		dict = registers[index]
		return dict.values()[0]
	else :
		return ERROR_VALUE_NOT_FOUND

def get_constants_name_from_value(constant_dict, value) :
	"""
		@param constant_dict : constant dictionary to consider
		@param value : value's constant name to retrieve
	
		@rtype : a string
	"""
	try:
		return constant_dict[value]
	
	except KeyError:
		log.error("The constant name corresponding to the value '%s' can not be found in the dictionary '%s'" % (value, constant_dict))
		return ERROR_CONSTANT_NAME_NOT_FOUND

#this part is getting the parameters from a method
def method_parameters(method):
    """
    @param method an EncodedMethod object
    
    @rtype if it has two  param p0 p1, then p0 is tranversed to v(n-1), p1 is tranversed to v(n)
           output v...   
    """
    #print (method.show_xref())
    #print (method.show_info())
    #print ("{} {}".format(method.get_class_name(),method.get_name()))
    try:
        desc = method.get_descriptor()
        pattern = re.compile('\((.*?)\)') 
        para_num = pattern.match(desc).groups()[0].count(';')

    except:
        print ("nothing compared") 

    notice = False
    parameters = []
    code = method.get_code()
    bc = code.get_bc()
    pattern = re.compile('v[0-9]+')
    pattern2 = re.compile('^v([0-9]+)$')
    for i in bc.get_instructions():
        instruction = "%s %s" % (i.get_name(), i.get_output())
        #print (instruction)
        if (instruction.find("Landroid/widget/EditText;->getText()")):
            #print ("\n\nGETTEXT FOUND!!!!!!!!\n\n")
            notice = True    
        
        for j in re.findall(pattern,instruction):
            temp = pattern2.match(j).groups()[0]            
            if temp not in parameters:
               parameters.append(temp)  

    parameters.sort(key = int)
    length = len(parameters)
    para = []
    for i in xrange(para_num):
        temp = parameters[length - para_num + i]
        tt = str(temp)
        para.append(tt) 
    
    del parameters
    return para_num,para,notice

# this part is to get the corresponding 
def index_parameters_dependence(data_dependent, para):
    index = []
    for i in data_dependent:
        if i in para:  
           index.append(int (para.index(i))) 
    index = None 
    index = INIT          
    return index  

def recursive_find(x, method,  method_call_index_to_find, index, depth):
    
    class_name = method.get_class_name()
    method_name = method.get_name()
    para_num, para, notice  = method_parameters(method)
    trigger_option = False 
    
    trigger_option, data_dependent = parameters_dependence_find_one_by_one(x, method,  method_call_index_to_find, index)
    index1   = index_parameters_dependence(data_dependent, para)
    depth = depth + 1

    if trigger_option :
       return trigger_option

    elif not (len(data_dependent) > 0):
       return trigger_option

    elif not (len(index1) > 0) :
       return trigger_option
    
    elif (not trigger_option) and (para_num > 0) and (depth < 5) : 

       structural_analysis_results = x.tainted_packages.search_methods( class_name,  method_name, ".")
       for result in xrange(len(structural_analysis_results)) :
           method1 = structural_analysis_results[result].get_method()
           class_name1 = method1.get_class_name()
           method_name1 = method1.get_name()
           #print ("data dependence transfered\n{} {}  --> {} {}".format(class_name1,method_name1,class_name,method_name))
           if (class_name1 != class_name) or  (method_name != method_name1) :
                 method_call_index_to_find1 = structural_analysis_results[result].get_idx()
                 F1 = recursive_find(x, method1,  method_call_index_to_find1, index1, depth)	                
                 if F1:
                    return F1 
    #raw_input() 
    return False

def data_flow_analysis(tab, result, x) :
	"""
		@param tab : structural analysis results tab
		@param result : current iteration
		@param x : a VMAnalysis instance
	
		@rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
	"""
	method = tab[result].get_method()
	method_call_index_to_find = tab[result].get_idx()
        class_name = method.get_class_name()
        method_name = method.get_name()
        #index = [ int(i) for i in xrange(0,6)]
        index = INIT
        """
        trigger_option, data_dependent = parameters_dependence_find_one_by_one(x, method,  method_call_index_to_find, index)
        index  = index_parameters_dependence(data_dependent, para) 
        print (trigger_option)
        print (data_dependent)
        print (para)  
        print (index)
        """
        depth = 1
        FFF = recursive_find(x, method,  method_call_index_to_find, index, depth)
        
        #print (FF)
        return  FFF 

        #raw_input("    FINALLY    ")
	#log.info("Class '%s' - Method '%s' - register state before call %s" % (tab[result].get_class_name(),tab[result].get_name(), registers))
	"""
	class_str 	= "Class '%s'" % tab[result].get_class_name()
	method_str 	= "Method '%s'" % tab[result].get_name()
	regs_str 	= "Register state before call %s" %  registers
	
	formatted_str = "{0:50}- {1:35}- {2:30}".format(class_str,method_str, regs_str)
	return registers
        """	
#########################
#The core codes has been modified a lot to meet the data-flow-trace  
#among methods
#########################
