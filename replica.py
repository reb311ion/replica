#Automatically enhance Ghidra auto analysis
#@author @reb311ion
#@keybinding shift R
#@category Analysis
#@toolbar replica.png

import re
import json 
import struct
import ghidra.app.plugin.core.analysis.ReferenceAddressPair
import ghidra.app.script.GhidraScript
import ghidra.program.model.address.Address
import ghidra.program.model.mem.Memory
import ghidra.program.util.ProgramMemoryUtil
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import java.util.ArrayList as ArrayList
import ghidra.program.util.ProgramMemoryUtil as ProgramMemoryUtil
import ghidra.app.plugin.core.analysis.AutoAnalysisManager as AutoAnalysisManager
from ghidra.program.model.listing import * 
from ghidra.program.model.symbol import * 
from java.util import * 
from time import sleep
from ghidra.program.model.symbol.SourceType import *
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address.Address import *
from ghidra.app.script import GhidraScript
from ghidra.app.services import DataTypeManagerService
from ghidra.framework.plugintool import PluginTool
from ghidra.program.model.data import DataType
from ghidra.program.model.data import DataTypeManager
from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder
from ghidra.program.model.address import Address
from ghidra.program.model.lang import LanguageCompilerSpecPair
from ghidra.program.model.listing import Program
from ghidra.util import Msg
from java.lang import IllegalArgumentException
from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import FlowType
from data import *
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.symbol.SymbolUtilities import *


try: 
	open(dbPath).read()
except:
	dbPath = askFile("db.json path", "Choose file:")
	dbPath = str(dbPath)
	db = open(dbPath.replace("db.json","data.py"),"a")
	db.write("\n\n")
	db.write("dbPath = r'" + dbPath + "'")
	db.close()

def getDataType(dataType):
	tool = state.getTool()
	service = tool.getService(DataTypeManagerService)
	dataTypeManagers = service.getDataTypeManagers()
	for manager in dataTypeManagers:
		dt = manager.getDataType(dataType.replace(" ","").replace("*",""))
		if dt != None: 
			if "*" in dataType:
				for i in range(len(re.findall(r"\*",str(dataType)))):
					dt = manager.getPointer(dt)
			else:
					pass
			return dt
	return None  

def getFunctionStartEnd(function):
	functionBody = function.getBody().toList()
	minAddress = int("0x" + functionBody[0].minAddress.toString(),16)
	if len(functionBody) > 1:
		maxAddress = int("0x" + functionBody[-1].maxAddress.toString(),16)
	else:
		maxAddress = int("0x" + functionBody[0].maxAddress.toString(),16)	
	return minAddress,maxAddress

def isValidEnd(instruction):
    if instruction.isInDelaySlot():
        instruction = getInstructionAt(instruction.getFallFrom())
    if instruction.getFlowType() == FlowType.TERMINATOR:
        return True
    return False

def disasFun(addr):
	code         = ""
	programList  = currentProgram.getListing()
	function     = getFunctionContaining(addr)
	instruction  = programList.getInstructionAt(function.getEntryPoint())
	while instruction:
	    mnemonic = instruction.mnemonicString
	    code += instruction.address.toString() + " " + instruction.toString()
	    code += "\n"
	    if isValidEnd(instruction):
	    	return code
	    instruction = instruction.next

def isWrapperFunction(function):
	programList  = currentProgram.getListing()
	instruction  = programList.getInstructionAt(function.getEntryPoint())
	callsCounter = 0
	while instruction:
		if FlowType.isJump(instruction.getFlowType()):
			return False
		if FlowType.isCall(instruction.getFlowType()):
			callsCounter += 1
		if callsCounter > 1:
			return False
		if isValidEnd(instruction):
			return True
		instruction = instruction.next

def checkString(addr):
    data = getDataAt(addr)
    sym  = getSymbolAt(addr)
    if data:
	    dataCmp = data.getBaseDataType().getName().lower()
	    if ("string" == dataCmp) or ("unicode" == dataCmp): 
	        return data.getValue()
    if sym is not None:
    	symCmp = str(sym).lower()
    	if symCmp.startswith("ptr_s_") or symCmp.startswith("ptr_u_") or symCmp.startswith("rep_ptr_s_") or symCmp.startswith("rep_ptr_u_"):
			return str(sym)
    return None

def getaddressListFromDisas(code):
    pattern = "0x[a-fA-F0-9]{6,}"
    return re.findall(pattern,code)

def setcommnet(addr,msg):
	listing = currentProgram.getListing()
	codeUnit = listing.getCodeUnitAt(addr)
	codeUnit.setComment(codeUnit.PLATE_COMMENT, msg)

def FormatD(description,tabsize,termsize=100):
    data = ""
    lines = []
    line = []
    tabsize = " " * tabsize
    Tab = False
    descriptionarr = description.split(" ")

    for index in descriptionarr:
        line.append(index)
        if len(" ".join(line)) >= (int(termsize) - 30):
            lines.append(" ".join(line))
            line = []
    if lines == []:
        data += "\n"
        data += " ".join(line)
    else:
        for index in lines:
            if Tab:
                data += "\n"        
                data += tabsize + index
            else:
                data += "\n"
                data += index
            Tab = True    
    if not line == [] and Tab == True:
        data += "\n"
        data += tabsize + " ".join(line)
    return data[1:]

def getApiInfo(function,database):
    msg = ""
    function = str(function)
    if function[-1] == "A" or function[-1] == "W":
    	function = function[:-1]
    if function[:-2] == "EX":
    	function = function[:-2]
    for i in database['msdn']['functions']['function']:                                                                                                                          
        if  i['name'] == function:                                                                                                                      
            msg += 'Name: '  + i['name']    
            msg += "\n"                                                                                                                     
            msg += '\nDLL: ' + i['dll']   
            msg += "\n"                                                                                                                                      
            msg += '\nDescription: ' + FormatD(i['description'],0)                                                                                                                        
            try:                                                                                                                      
            	argz = i['arguments']['argument']  
            except:
            	argz = None    
            if argz:
				msg += "\n"
				msg += '\nArguments:     '
				msg += "\n"                                                                                                                       
				if 'dict' in str(type(argz)):                                                                                                                          
				    msg += '\n   Name: ' + str(argz['name'])
				    msg += "\n"                                                                                                              
				    msg += '   Description: ' + FormatD(argz['description'],9)
				    msg += "\n"                                                                                                
				elif 'list' in str(type(argz)): 
				    for arg in argz: 
				        msg += '\n   Name: ' + str(arg['name'])
				        msg += "\n"
				        msg += '   Description: ' + FormatD(arg['description'],16)
				        msg += "\n"   
            if i['returns']:
                 msg += "\n" + FormatD(i['returns'],0)
    return msg

def findAllReferences(addr, taskMonitor):
	directReferenceList = ArrayList()
	results = ArrayList()
	toAddr = currentProgram.getListing().getCodeUnitContaining(addr).getMinAddress()
	try:
		ProgramMemoryUtil.loadDirectReferenceList(currentProgram, 1, toAddr, None,directReferenceList, taskMonitor)
	except:
		return Collections.emptyList()	
	for rap in directReferenceList:
		fromAddr = currentProgram.getListing().getCodeUnitContaining(rap.getSource()).getMinAddress()
		if (not fromAddr in results):
			results.add(fromAddr)
	ri = currentProgram.getReferenceManager().getReferencesTo(toAddr)
	while (ri.hasNext()):
		r = ri.next()
		fromAddr = r.getFromAddress()
		if (not fromAddr in results):
			results.add(fromAddr)
	return results

def getWrapperFunctionName(functionName):
    if "rep_wrap" in functionName:
    	wrapNumber = int(functionName.split("_")[2]) + 1
    	return "rep_wrap_" + str(wrapNumber) + "_" + "".join(functionName.split("_")[3:])
    else:
    	return "rep_wrap_0_" + functionName

def recoverStackString(addr):
  stackStr = ""
  inst = getInstructionAt(addr)
  maxaddr = addr
  while inst and inst.getScalar(1):
    value = inst.getScalar(1).value
    if value == 0x00 and stackStr != "":
        return stackStr,str(maxaddr)   
    stackStrPart = ""
    while value > 0:
        stackStrPart += chr(value&0xff)
        value = value>>8
    stackStr += stackStrPart
    try:
        if (inst.getNext().getScalar(1) == None) and (inst.getNext().getNext().getScalar(1) != None): 		
            inst = inst.getNext()
    except:
    	pass
    inst = inst.getNext()
    maxaddr = inst.address
  return stackStr,str(maxaddr)

def getDataTypeWrap(dt):
	ptr = ""
	if len(dt) > 1:
		ptr = " " + dt[1:]
	if "1" in dt:
		dt = getDataType("/byte" + ptr)
	elif "2" in dt:
		dt = getDataType("/word" + ptr)
	elif "4" in dt:
		dt = getDataType("/dword" + ptr)
	elif "8" in dt:
		dt = getDataType("/qword" + ptr)
	else:
		return None
	return dt

def fixUndefinedDataTypes():
	monitor.setMessage("Fixing Undefined Data Types")	
	function =  getFirstFunction()
	while function is not None:
		for var in function.getAllVariables():
			varBefore = str(var)
			dt = str(var.getDataType())
			if "undefined" in dt:
				dt = dt.replace("undefined","")
				dt = getDataTypeWrap(dt)
				if dt:
					var.setDataType(dt,USER_DEFINED)
					print "[+] " + str(function.getName()) + ": " + varBefore + " -> " + str(dt)
		function = getFunctionAfter(function)
	return 0

def Pack(const):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<Q", val)))
    return  bytes(bytearray(byte_array))

def isValidEnd(last_instruction):
    if last_instruction is None:
        return False

    if last_instruction.isInDelaySlot():
        last_instruction = getInstructionAt(last_instruction.getFallFrom())

    if last_instruction.getFlowType() == FlowType.TERMINATOR:
        return True
    return False

def detectUndefinedFunctions():
     monitor.setMessage("Defining Undefined Functions")
     programList  = currentProgram.getListing()
     instruction  = programList.getInstructions(1)
     while instruction.hasNext() and not monitor.isCancelled():
        inst = instruction.next()
        addressString = inst.getAddress().toString()
        mnemonic      = inst.getMnemonicString()
        x86Fun        = (inst.toString() == "PUSH EBP" and inst.next.toString() == "MOV EBP,ESP")
        x64Fun        = (inst.toString() == "PUSH RBP" and inst.next.toString() == "MOV RBP,RSP")
        if getFunctionAt(inst.getAddress()) == None and (x86Fun or x64Fun):
            createFunction(inst.getAddress(),"FUN_" + addressString)
            createdFunction        = getFunctionAt(inst.getAddress())
            minAddress, maxAddress = getFunctionStartEnd(createdFunction)
            try:
                if isValidEnd(getInstructionAt(toAddr(maxAddress))):
                    print("[+] Created Function: " + "FUN_" + addressString)
                else:
                    removeFunction(createdFunction)
            except:
                pass

# the decompiler was slower so it was replaced with renameFunctionsBasedOnStrRef function.
def renameFunctionsBasedOnstringRefrencesUsingTheDecompiler():
    monitor.setMessage("Rename Functions Based on string refrences ")    
    function =  getFirstFunction()
    decompinterface = DecompInterface()
    decompinterface.openProgram(currentProgram)
    uniqueList = []
    while function is not None and not monitor.isCancelled():
        try:
            tokengrp   = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
            code       = tokengrp.getDecompiledFunction().getC()
            pattern1   = r"\"[a-zA-Z0-9 .,\-\*\/\[\]\{\}\!\@\#\$\%\^\&\(\)\=\~\:\"\'\\\+\?\>\<\`\_\;]+\""
            pattern2   = r'[ .,\-\*\/\[\]\{\}\!\@\#\$\%\^\&\(\)\=\~\:\"\'\\\+\?\>\<\`]+'
            stringList = re.findall(pattern1,code)
            if not stringList == []:
                for unique in stringList:  
                    if unique not in uniqueList: 
                        uniqueList.append(unique)
                name = re.sub(pattern2,"","_".join(uniqueList))
                if len(name) > 15:
                    name = name[:15]
                functionName = "rep_s_fun_" + str(function.getEntryPoint()) + "_" + name
                print functionName               
                function.setName(functionName,USER_DEFINED)
        except:
            pass
    function = getFunctionAfter(function)
    return 0

def tagFunctions():
	monitor.setMessage("Tagging Functions With Called API Family And Names")	
	function =  getFirstFunction()
	while function is not None and not monitor.isCancelled():
		if function.getName().startswith("FUN"):
			for calledFunction in function.getCalledFunctions(monitor):
				tagName = ""
				for tag in apiTags.keys():
					for value in apiTags[tag]:
						if value in str(calledFunction):
							tagName = "rep__" + tag + "_" + str(function.getEntryPoint()) + "_" 
				if tagName == "":
					tagName = "rep_" + str(function.getEntryPoint()) + "_"
				if not "FUN_" in str(calledFunction) and not "rep_" in str(calledFunction):				
					functionNewName = tagName + str(calledFunction)
					print str(function.getName()) + " -> "  + functionNewName					
					function.setName(functionNewName,USER_DEFINED)
					break
		function = getFunctionAfter(function)
	return 0

def detectWrapperFunctions():
	monitor.setMessage("Labeling Wrapper Functions")
	FunctionRenamed = True
	while FunctionRenamed: 
		function =  getFirstFunction()
		FunctionRenamed = False
		while function is not None and not monitor.isCancelled():
			FunctionName = str(function.getName())
			if FunctionName.startswith("FUN_") or FunctionName.startswith("rep"):
				calledFunction = function.getCalledFunctions(monitor)
				if len(calledFunction) == 1 and isWrapperFunction(function):
					functionNewName = getWrapperFunctionName(str(list(calledFunction)[0]))
					isFunctionRecursive = str(function.getName()) == str(list(calledFunction)[0])

					if str(function.getName()) != functionNewName and not isFunctionRecursive:
						print "[+] " + str(function.getName()) + " -> "  + functionNewName	
						FunctionRenamed = True
						function.setName(functionNewName,USER_DEFINED)
			function = getFunctionAfter(function)
	return 0

def cleanUpDisassembly():
	monitor.setMessage("Cleaning Up Disassembly")
	bmgr        = currentProgram.getBookmarkManager()
	listing     = currentProgram.getListing()
	previousSet = None
	while (True):
		badAddr = bmgr.getBookmarkAddresses("Error")
		bai = badAddr.getAddresses(True)
		while (bai.hasNext()):
			ba = bai.next()
			bm = bmgr.getBookmark(ba, "Error", "Bad Instruction")
			if (bm != None):
				contextReg = currentProgram.getProgramContext().getRegister("TMode")
				baEnd = ba
				if (listing.getCodeUnitAt(ba) != None):
					baEnd = listing.getCodeUnitAt(ba).getMaxAddress()
				while (getDataContaining(baEnd.add(4)) != None):
					baEnd = getDataContaining(baEnd.add(4)).getMaxAddress()
				while (getDataContaining(ba.subtract(1)) != None):
					ba = getDataContaining(ba.subtract(1)).getAddress()
				listing.clearCodeUnits(ba, baEnd, False)
				if (contextReg != None):
					paddr = listing.getInstructionBefore(ba).getAddress()
					if (paddr != None):
						rv = currentProgram.getProgramContext().getRegisterValue(contextReg,paddr)
						currentProgram.getProgramContext().setRegisterValue(ba, baEnd, rv)
				bmgr.removeBookmark(bm)

		while (AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing()):
			sleep(500)
		if (badAddr.equals(previousSet)):
			break
		previousSet = badAddr

def fixMissingDisassembly():
	monitor.setMessage("Fixing missing instructions")
	memoryBlocks = getCurrentProgram().getMemory().getBlocks()
	for block in memoryBlocks:
		if block.isExecute():
			blockStart = int("0x" + block.getStart().toString(),16)
			blockEnd   = int("0x" + block.getEnd().toString(),16)
			for addr in range(blockStart,blockEnd):
				addr = toAddr(addr)
				alignment = currentProgram.getLanguage().getInstructionAlignment()
				if getInstructionAt(addr) == None and addr.offset % alignment == 0:
					disassemble(addr)
	cleanUpDisassembly()

def setApiInfoComment():
	db = open(dbPath).read()
	loadedDB = json.loads(db)
	monitor.setMessage("Setting MSDN API Info For Functions")
	function =  getFirstFunction()
	while function is not None and not monitor.isCancelled():
		 FunctionName = str(function.getName())			
		 if not "FUN_" in FunctionName:
		 	msg = getApiInfo(FunctionName,loadedDB)
	 		if msg != None and len(msg) > 10:
				setcommnet(function.getEntryPoint(),msg)
				print "[+] " + FunctionName
		 function = getFunctionAfter(function)
	return 0

def detectIndirectStringReferences():
	listing = currentProgram.getListing()
	memory = currentProgram.getMemory()
	symbolTable = currentProgram.getSymbolTable()
	monitor.setMessage("Labeling Indirect References To Strings")
	strAddrSet = ArrayList()
	dataIterator = listing.getDefinedData(True)
	while (dataIterator.hasNext() and not monitor.isCancelled()):
		nextData = dataIterator.next()
		type = nextData.getDataType().getName().lower()
		if ("unicode" in type or "string" in type):
			strAddrSet.add(nextData.getMinAddress())
	if (strAddrSet.size() == 0):
		popup("No strings found.  Try running 'Search -> For Strings...' first.")
		return 0;
	for i in range(strAddrSet.size()):
		strAddr = strAddrSet.get(i)
		allRefAddrs = findAllReferences(strAddr, monitor)
		for j in range(allRefAddrs.size()):
			refFromAddr = allRefAddrs.get(j)
			if (listing.getInstructionContaining(refFromAddr) == None): ## if not instruction and has addresses so its pointer 
				refRef = getReferencesTo(refFromAddr)
				if (len(refRef) > 0):
					newLabel = "rep_ptr_" + str(listing.getDataAt(strAddr).getLabel()) + "_" + str(allRefAddrs.get(j))
					print("[+] " + newLabel)
					symbolTable.createLabel(allRefAddrs.get(j), newLabel, USER_DEFINED)
	return 0

def detectIndirectFunctionReferences():
	listing = currentProgram.getListing()
	symbolTable = currentProgram.getSymbolTable()
	monitor.setMessage("Labeling Indirect References To Functions")
	function =  getFirstFunction()
	while function is not None and not monitor.isCancelled():
		allRefAddrs = findAllReferences(function.getEntryPoint(), monitor)
		for ref in range(allRefAddrs.size()):
			refFromAddr = allRefAddrs.get(ref)
			if (listing.getInstructionContaining(refFromAddr) == None):
				refRef = getReferencesTo(refFromAddr)
				if (len(refRef) > 0):
					newLabel = "rep_ptr_f_" + str(function.getName()) + "_" + str(allRefAddrs.get(ref))
					print("[+] " + newLabel)
					symbolTable.createLabel(allRefAddrs.get(ref), newLabel, USER_DEFINED)		

		function = getFunctionAfter(function)
	return 0

def renameFunctionsBasedOnStrRef():
    monitor.setMessage("Rename Functions Based on string refrences ")    
    function =  getFirstFunction()
    while function is not None and not monitor.isCancelled():
        if function.getName().startswith("FUN"):
                addressList = getaddressListFromDisas(disasFun(function.getEntryPoint()))
                if addressList:
                    for address in addressList:
                        name = checkString(toAddr(address))
                        if name != None: 
                            if len(name) < 3:
                                continue
                            name = re.sub(r'[^a-zA-Z0-9_.]+','',name[:50])
                            functionName = "rep_" + str(function.getEntryPoint()) + "_s_" +  name 
                            print "[+] " + function.getName() + " -> " + functionName             
                            function.setName(functionName,USER_DEFINED)
                            break
        function = getFunctionAfter(function)
    return 0

def detectCryptoConstants():
    monitor.setMessage("Labeling Crypto Constants Within The Binary")
    symbolTable = currentProgram.getSymbolTable()
    for const in non_sparse_consts:
        const["byte_array"] = Pack(const)
        found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), const["byte_array"], None, True, monitor)
        if found != None:
            labelName = "rep_crypto_constant_" + const['algorithm'] + "_" + const['name']
            print "[+] " + const['algorithm'] + " " + const['name'] + " 0x" + str(found) + " -> " + labelName
            symbolTable.createLabel(found, labelName, USER_DEFINED)

    listing = currentProgram.getListing() 
    instruction = listing.getInstructions(1)
    while instruction.hasNext():            
        inst = instruction.next()
        for const in sparse_consts:
	        if str(const["array"][0]).upper() == str(inst.getScalar(1)).upper():
                    labeladdr = inst.getAddress()
	            for val in const["array"][1:]:
	                inst = instruction.next()
	                if not str(val).upper() == str(inst.getScalar(1)).upper():
	            	    if const['name'] == "SHA1_H" and const['array'][-1]:
                                    labelName = "rep_crypto_constant_MD5_initstate"
	            		    print "[+] " + "MD5_initstate"  + " 0x" + str(labeladdr) + " -> " + labelName
	            		    symbolTable.createLabel(labeladdr, labelName, USER_DEFINED)
	            	    break
	            else:
                        labelName = "rep_crypto_constant_" + const['algorithm'] + "_" + const['name']
                        print "[+] " + const['name'] + " 0x" + str(labeladdr) + " -> " + labelName
                        symbolTable.createLabel(labeladdr, labelName, USER_DEFINED)

def detectStackStrings():
  monitor.setMessage("Detecting Stack Strings")	
  programList  = currentProgram.getListing()
  instruction  = programList.getInstructions(1)
  while instruction.hasNext() and not monitor.isCancelled():
      inst = instruction.next()
      instStr = str(inst.getScalar(1)).replace("0x","")
      if not instStr == "None" and (len(instStr) % 2) == 0 and not "-" in instStr:
          stackStr, maxAddr = recoverStackString(inst.address)
          FilteredStackStr  = re.sub(r'[^a-zA-Z0-9 .,\-\*\/\[\]\{\}\!\@\#\$\%\^\&\(\)\=\~\:\"\'\\\+\?\>\<\`\_\;]+','', stackStr)
          if len(FilteredStackStr) > 4 and FilteredStackStr == stackStr:
              print "[+] " + str(inst.address) + " " + stackStr
              codeUnit = programList.getCodeUnitAt(inst.address)
              codeUnit.setComment(codeUnit.PRE_COMMENT, stackStr)

          while str(inst.address) != maxAddr:
              inst = instruction.next()


def fixUndefinedData():
    data_sections = []
    addr_factory = currentProgram.getAddressFactory()
    memory_manager = currentProgram.getMemory()
    address_ranges = memory_manager.getLoadedAndInitializedAddressSet()
    executable_set = memory_manager.getExecuteSet()
    addr_view = address_ranges.xor(executable_set)
    for section in addr_view:
        new_view = addr_factory.getAddressSet(section.getMinAddress(),section.getMaxAddress())
        data_sections.append(new_view)

    for section in data_sections:
        print '[+] Section {} - {}'.format(section.getMinAddress(),section.getMaxAddress())
        start_addr = section.getMinAddress()
        end_addr = section.getMaxAddress()
        strings = findStrings(section, 1, 1, True, True)
        for string in strings:
            if getUndefinedDataAt(string.getAddress()):
                try:
                    createAsciiString(string.getAddress())
                except:
                    continue

        undefined_data = getUndefinedDataAt(start_addr)
        if undefined_data is None:
            undefined_data = getUndefinedDataAfter(start_addr)

        while undefined_data is not None and undefined_data.getAddress() < end_addr:
            undefined_addr = undefined_data.getAddress()
            undefined_data = getUndefinedDataAfter(undefined_addr)
            try:
                createDWord(undefined_addr)
            except:
                continue

if __name__ == '__main__':
	try:

		choices = askChoices("Choices 2", "Please choose from Analysis Options.", 
		                      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
		                      ["Disassemble undefined instructions", "Detect and fix undefined functions",
		                       "Fix undefined datatypes","Set MSDN API info as comments", 
		                       "Tag Functions based on API calls", "Detect and mark wrapper functions",
		                       "Fix undefined data and strings", "Detect and label crypto constants",
		                       "Detect and label stack strings","Detect and label indirect string references",
		                       "Detect and label indirect function calls","Rename Functions Based on string refrences"])

		if 0 in choices:
			fixMissingDisassembly()
		if 1 in choices:
			detectUndefinedFunctions()
		if 2 in choices:
			fixUndefinedDataTypes()
		if 3 in choices:
			setApiInfoComment()	
		if 4 in choices:
			tagFunctions()
		if 5 in choices:
			detectWrapperFunctions()
		if 6 in choices:
			fixUndefinedData()
		if 7 in choices:
			detectCryptoConstants()
		if 8 in choices:
			detectStackStrings()
		if 9 in choices:
			detectIndirectStringReferences()
		if 10 in choices:
			detectIndirectFunctionReferences()
		if 11 in choices:
			renameFunctionsBasedOnStrRef()

	except IllegalArgumentException as error:
	    print error.toString()