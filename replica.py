# Automatically enhance Ghidra auto analysis
# @author @reb311ion
# @keybinding shift R
# @category Analysis
# @toolbar replica.png

import json
import re
import struct
from time import sleep

import ghidra.app.plugin.core.analysis.AutoAnalysisManager as AutoAnalysisManager
import ghidra.program.util.ProgramMemoryUtil as ProgramMemoryUtil
import java.util.ArrayList as ArrayList
from ghidra.app.decompiler import DecompInterface
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.address.Address import *
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.symbol.SymbolUtilities import *
from ghidra.util.task import ConsoleTaskMonitor
from java.lang import IllegalArgumentException
from java.util import *

from data import *

try:
    open(dbPath).read()
except:
    dbPath = askFile("db.json path", "Choose file:")
    dbPath = str(dbPath)
    db = open(dbPath.replace("db.json", "data.py"), "a")
    db.write("\n\n")
    db.write("dbPath = r'" + dbPath + "'")
    db.close()


def addrToInt(addr):
    return int("0x" + addr.toString(), 16)


def disasFun(addr, getBody=False):
    code = ""
    programList = currentProgram.getListing()
    function = getFunctionContaining(addr)
    start = function.getEntryPoint()
    instruction = programList.getInstructionAt(start)
    while instruction:
        code += instruction.address.toString() + " " + instruction.toString()
        code += "\n"
        if isValidEnd(instruction):
            if getBody:
                end = instruction.address
                return code, addrToInt(start), addrToInt(end)
            else:
                return code
        instruction = instruction.next


def getFunctionStartEnd(function):
    functionBody = function.getBody().toList()
    start = addrToInt(functionBody[0].minAddress)
    end = addrToInt(functionBody[-1].maxAddress)
    return start, end


def isWrapperFunction(function):
    programList = currentProgram.getListing()
    instruction = programList.getInstructionAt(function.getEntryPoint())
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
    sym = getSymbolAt(addr)
    if data:
        dataCmp = data.getBaseDataType().getName().lower()
        if ("string" == dataCmp) or ("unicode" == dataCmp):
            return data.getValue()
    if sym is not None:
        symCmp = str(sym).lower()
        if symCmp.startswith("ptr_s_") or symCmp.startswith("ptr_u_") or symCmp.startswith(
                "rep_ptr_s_") or symCmp.startswith("rep_ptr_u_"):
            return str(sym)
    return None


def getaddressListFromDisas(code):
    if code == None:
        return None
    pattern = "0x[a-fA-F0-9]{6,}"
    return re.findall(pattern, code)


def setcommnet(addr, msg):
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(addr)
    codeUnit.setComment(codeUnit.PLATE_COMMENT, msg)


def FormatD(description, tabsize, termsize=100):
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


def getApiInfo(function, database):
    msg = ""
    function = str(function)
    if function[-1] == "A" or function[-1] == "W":
        function = function[:-1]
    if function[:-2] == "EX":
        function = function[:-2]
    for i in database['msdn']['functions']['function']:
        if i['name'] == function:
            msg += 'Name: ' + i['name']
            msg += "\n"
            msg += '\nDLL: ' + i['dll']
            msg += "\n"
            msg += '\nDescription: ' + FormatD(i['description'], 0)
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
                    msg += '   Description: ' + FormatD(argz['description'], 9)
                    msg += "\n"
                elif 'list' in str(type(argz)):
                    for arg in argz:
                        msg += '\n   Name: ' + str(arg['name'])
                        msg += "\n"
                        msg += '   Description: ' + FormatD(arg['description'], 16)
                        msg += "\n"
            if i['returns']:
                msg += "\n" + FormatD(i['returns'], 0)
    return msg


def findAllReferences(addr, taskMonitor):
    directReferenceList = ArrayList()
    results = ArrayList()
    toAddr = currentProgram.getListing().getCodeUnitContaining(addr).getMinAddress()
    try:
        ProgramMemoryUtil.loadDirectReferenceList(currentProgram, 1, toAddr, None, directReferenceList, taskMonitor)
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
        return "rep_wrap_" + str(wrapNumber) + "_" + "_".join(functionName.split("_")[3:])
    else:
        return "rep_wrap_0_" + functionName


def recoverStackString(addr):
    stackStr = ""
    inst = getInstructionAt(addr)
    maxaddr = addr
    while inst and inst.getScalar(1):
        value = inst.getScalar(1).value
        if value == 0x00 and stackStr != "":
            return stackStr, str(maxaddr)
        stackStrPart = ""
        while value > 0:
            stackStrPart += chr(value & 0xff)
            value = value >> 8
        stackStr += stackStrPart
        try:
            if (inst.getNext().getScalar(1) == None) and (inst.getNext().getNext().getScalar(1) != None):
                inst = inst.getNext()
        except:
            pass
        inst = inst.getNext()
        maxaddr = inst.address
    return stackStr, str(maxaddr)


def getDataType(dataType, isArr=False, elm=0):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers()
    for manager in dataTypeManagers:
        dt = manager.getDataType(dataType.replace(" ", "").replace("*", ""))
        if dt != None:
            if "*" in dataType:
                for i in range(str(dataType).count("*")):
                    dt = manager.getPointer(dt)
            if isArr:
                if type(dt) == PointerDataType:
                    ln = dt.getDataType().getLength()
                else:
                    ln = dt.getLength()
                dt = ArrayDataType(dt, elm, ln)
            return dt
    return None


def getDataTypeWrap(dt, isArr=False, elm=0):
    ptr = ""
    if "*" in dt:
        ptr = " " + ('*' * dt.count("*"))
    if "1" in dt:
        dt = getDataType("/char" + ptr, isArr, elm)
    elif "2" in dt:
        dt = getDataType("/short" + ptr, isArr, elm)
    elif "4" in dt:
        dt = getDataType("/int" + ptr, isArr, elm)
    elif "8" in dt:
        dt = getDataType("/long" + ptr, isArr, elm)
    else:
        return None
    return dt


def fixUndefinedDataTypes():
    monitor.setMessage("Fixing Undefined Data Types")
    function = getFirstFunction()
    decompinterface = DecompInterface()
    decompinterface.openProgram(currentProgram)

    while function is not None:
        prt = False
        varList = []
        try:
            tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
            code = tokengrp.getDecompiledFunction().getC()
            for line in code.split("\n"):
                if line == "  \r":
                    break
                if prt:
                    varList.append(filter(None, line.split(";")[0].split(" ")))
                if line.startswith("{"):
                    prt = True
        except:
            pass

        for var in function.getAllVariables():
            varMsg = str(var)
            dt = str(var.getDataType())
            inx = 0
            if "undefined" in dt:
                for decVar in varList:
                    if len(decVar) > 1:
                        arr = False
                        if len(decVar) == 3:
                            try:
                                arr = True
                                inx = int(decVar[2].split("[")[1].split("]")[0])
                            except:
                                arr = False
                        if decVar[1].replace("*", "") == var.getName():
                            if not "undefined" in decVar[0]:
                                if '*' in decVar[1]:
                                    dt = getDataType("/" + decVar[0] + " " + ('*' * decVar[1].count("*")), arr, inx)
                                else:
                                    dt = getDataType("/" + decVar[0], arr, inx)
                            else:
                                if '*' in decVar[1]:
                                    dtlen = decVar[0].replace("undefined", "")
                                    if dtlen == "":
                                        dtlen = "1"
                                    dt = getDataTypeWrap(dtlen + ('*' * decVar[1].count("*")), arr, inx)
                                else:
                                    dt = getDataTypeWrap(decVar[0], arr, inx)

                if type(dt) == str:
                    dt = str(var.getDataType())
                    dt = dt.replace("undefined", "")
                    dt = getDataTypeWrap(dt)
                if dt:
                    try:
                        var.setDataType(dt, USER_DEFINED)
                        print "[+] " + str(function.getName()) + ": " + varMsg + " -> " + str(dt)
                    except:
                        pass
        function = getFunctionAfter(function)
    return 0


def Pack(const):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            byte_array += list(map(lambda x: x if type(x) == int else ord(x), struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            byte_array += list(map(lambda x: x if type(x) == int else ord(x), struct.pack("<Q", val)))
    return bytes(bytearray(byte_array))


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
    programList = currentProgram.getListing()
    instruction = programList.getInstructions(1)
    while instruction.hasNext() and not monitor.isCancelled():
        inst = instruction.next()
        instAddr = inst.getAddress()
        addressString = instAddr.toString()
        mnemonic = inst.getMnemonicString()
        instref = getReferencesTo(instAddr)
        if instref.tolist() != []:
            isCalled = False
            for ref in instref:
                if ref.getReferenceType().isCall() or ref.getReferenceType().isData():
                    isCalled = True
                    break
            if getFunctionAt(instAddr) == None and isCalled:
                createFunction(instAddr, "FUN_" + addressString)
                createdFunction = getFunctionAt(instAddr)
                if createdFunction != None:
                    try:
                        code, start, end = disasFun(createdFunction.getEntryPoint(), True)
                        minAddr, maxAddr = getFunctionStartEnd(createdFunction)
                        if maxAddr >= end:
                            print("[+] Created Function: " + "FUN_" + addressString)
                        else:
                            removeFunction(createdFunction)
                    except:
                        pass


def tagFunctions():
    monitor.setMessage("Tagging Functions With Called API Family And Names")
    function = getFirstFunction()
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
                    print "[+]" + str(function.getName()) + " -> " + functionNewName
                    function.setName(functionNewName, USER_DEFINED)
                    break
        function = getFunctionAfter(function)
    return 0


def detectWrapperFunctions():
    monitor.setMessage("Labeling Wrapper Functions")
    FunctionRenamed = True
    while FunctionRenamed:
        function = getFirstFunction()
        FunctionRenamed = False
        while function is not None and not monitor.isCancelled():
            FunctionName = str(function.getName())
            if FunctionName.startswith("FUN_") or FunctionName.startswith("rep"):
                calledFunction = function.getCalledFunctions(monitor)
                if len(calledFunction) == 1 and isWrapperFunction(function):
                    functionNewName = getWrapperFunctionName(str(list(calledFunction)[0]))
                    isFunctionRecursive = str(function.getName()) == str(list(calledFunction)[0])

                    if str(function.getName()) != functionNewName and not isFunctionRecursive:
                        print "[+] " + str(function.getName()) + " -> " + functionNewName
                        FunctionRenamed = True
                        function.setName(functionNewName, USER_DEFINED)
            function = getFunctionAfter(function)
    return 0


def cleanUpDisassembly():
    monitor.setMessage("Cleaning Up Disassembly")
    bmgr = currentProgram.getBookmarkManager()
    listing = currentProgram.getListing()
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
                        rv = currentProgram.getProgramContext().getRegisterValue(contextReg, paddr)
                        currentProgram.getProgramContext().setRegisterValue(ba, baEnd, rv)
                bmgr.removeBookmark(bm)
        else:
            break
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
            blockStart = int("0x" + block.getStart().toString(), 16)
            blockEnd = int("0x" + block.getEnd().toString(), 16)
            for addr in range(blockStart, blockEnd):
                addr = toAddr(addr)
                alignment = currentProgram.getLanguage().getInstructionAlignment()
                if getInstructionAt(addr) == None and addr.offset % alignment == 0:
                    disassemble(addr)
    cleanUpDisassembly()


def setApiInfoComment():
    db = open(dbPath).read()
    loadedDB = json.loads(db)
    monitor.setMessage("Setting MSDN API Info For Functions")
    function = getFirstFunction()
    while function is not None and not monitor.isCancelled():
        FunctionName = str(function.getName())
        if not "FUN_" in FunctionName:
            msg = getApiInfo(FunctionName, loadedDB)
            if msg != None and len(msg) > 10:
                setcommnet(function.getEntryPoint(), msg)
                print "[+] " + FunctionName
        function = getFunctionAfter(function)
    return 0


def renameFunctionsBasedOnStrRef():
    monitor.setMessage("Rename Functions Based on string refrences ")
    function = getFirstFunction()
    while function is not None and not monitor.isCancelled():
        if function.getName().startswith("FUN"):
            addressList = getaddressListFromDisas(disasFun(function.getEntryPoint()))
            if addressList:
                for address in addressList:
                    name = checkString(toAddr(address))
                    if name != None:
                        if len(name) < 3:
                            continue
                        name = re.sub(r'[^a-zA-Z0-9_.]+', '', name[:50])
                        functionName = "rep_" + str(function.getEntryPoint()) + "_s_" + name
                        print "[+] " + function.getName() + " -> " + functionName
                        function.setName(functionName, USER_DEFINED)
                        break
        function = getFunctionAfter(function)
    return 0


def detectCryptoConstants():
    monitor.setMessage("Labeling Crypto Constants Within The Binary")
    symbolTable = currentProgram.getSymbolTable()
    for const in non_sparse_consts:
        const["byte_array"] = Pack(const)
        found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), const["byte_array"], None, True,
                                                     monitor)
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
                            print "[+] " + "MD5_initstate" + " 0x" + str(labeladdr) + " -> " + labelName
                            symbolTable.createLabel(labeladdr, labelName, USER_DEFINED)
                        break
                else:
                    labelName = "rep_crypto_constant_" + const['algorithm'] + "_" + const['name']
                    print "[+] " + const['name'] + " 0x" + str(labeladdr) + " -> " + labelName
                    symbolTable.createLabel(labeladdr, labelName, USER_DEFINED)


def detectStackStrings():
    monitor.setMessage("Detecting Stack Strings")
    programList = currentProgram.getListing()
    instruction = programList.getInstructions(1)
    while instruction.hasNext() and not monitor.isCancelled():
        inst = instruction.next()
        instStr = str(inst.getScalar(1)).replace("0x", "")
        if not instStr == "None" and (len(instStr) % 2) == 0 and not "-" in instStr:
            stackStr, maxAddr = recoverStackString(inst.address)
            FilteredStackStr = re.sub(r'[^a-zA-Z0-9 .,\-\*\/\[\]\{\}\!\@\#\$\%\^\&\(\)\=\~\:\"\'\\\+\?\>\<\`\_\;]+', '',
                                      stackStr)
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
    is64Bit = "64" in currentProgram.language.toString()

    executable_set = memory_manager.getExecuteSet()
    addr_view = address_ranges.xor(executable_set)
    for section in addr_view:
        new_view = addr_factory.getAddressSet(section.getMinAddress(), section.getMaxAddress())
        data_sections.append(new_view)

    for section in data_sections:
        print '[+] Section {} - {}'.format(section.getMinAddress(), section.getMaxAddress())
        startAddr = section.getMinAddress()
        endAddr = section.getMaxAddress()

        for addr in range(addrToInt(startAddr), addrToInt(endAddr)):
            try:
                addr = toAddr(addr)
                if getSymbolAt(addr).getSymbolType().toString() == "Label" and (
                        getByte(addr) > 31 and getByte(addr) < 128):
                    enc = 1
                    while True:
                        addrPlus = toAddr(addrToInt(addr) + enc)
                        addrByte = getByte(addrPlus)
                        if not (((addrByte > 31 and addrByte < 128) or addrByte == 0) and getSymbolAt(
                                addrPlus) == None):
                            break
                        enc += 1
                    if enc >= 4:
                        createAsciiString(addr, enc)
            except:
                continue

        undefinedData = getUndefinedDataAt(startAddr)
        if undefinedData is None:
            undefinedData = getUndefinedDataAfter(startAddr)

        while undefinedData is not None and undefinedData.getAddress() < endAddr:
            undefinedAddr = undefinedData.getAddress()
            undefinedData = getUndefinedDataAfter(undefinedAddr)
            try:
                if is64Bit:
                    createQWord(undefinedAddr)
                else:
                    createDWord(undefinedAddr)

            except:
                continue


def createBookMark(addr, category, description):
    bm = currentProgram.getBookmarkManager()
    bm.setBookmark(addr, "Info", category, description)


def isRef(addr, hint):
    if getReferencesTo(addr).tolist() != []:
        return "Referenced " + hint
    else:
        return hint


def bookMarkStringHints():
    monitor.setMessage("Book Marking String Hint")
    listing = currentProgram.getListing()
    monitor.setMessage("BookMarking Intersting Strings [Hints]")
    dataIterator = listing.getDefinedData(True)
    while (dataIterator.hasNext() and not monitor.isCancelled()):
        data = dataIterator.next()
        strType = data.getDataType().getName().lower()
        matchStr = str(data.getValue())
        if ("unicode" in strType or "string" in strType) and matchStr:
            for hint in stringHint.keys():
                for value in stringHint[hint]:
                    if hint == "Extension Hint":
                        if matchStr.endswith(value) or (value + " ") in matchStr:
                            hint = isRef(data.getAddress(), hint)
                            createBookMark(data.getAddress(), "Replica", hint)
                            print "[+] " + hint + ": " + repr(matchStr)
                    else:
                        if value == matchStr or (len(value) >= 6 and value in matchStr):
                            hint = isRef(data.getAddress(), hint)
                            createBookMark(data.getAddress(), "Replica", hint)
                            print "[+] " + hint + ": " + repr(matchStr)
    return 0


if __name__ == '__main__':
    try:

        choices = askChoices("Choices", "Please choose from Analysis Options.",
                             [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                             ["Disassemble missed  instructions", "Detect and fix missed  functions",
                              "Fix undefined datatypes", "Set MSDN API info as comments",
                              "Tag Functions based on API calls", "Detect and mark wrapper functions",
                              "Fix undefined data and strings", "Detect and label crypto constants",
                              "Detect and comment stack strings", "Rename Functions Based on string references",
                              "Bookmark String Hints"])

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
            renameFunctionsBasedOnStrRef()
        if 10 in choices:
            bookMarkStringHints()

    except IllegalArgumentException as error:
        print error.toString()
