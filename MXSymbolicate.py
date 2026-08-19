#!/usr/bin/env python3
import json
import os, sys
import subprocess
import struct
import re
import datetime
import argparse

# From mac/exception_types.h, as per https://developer.apple.com/documentation/metrickit/mxcrashdiagnostic/3552297-exceptiontype?language=objc
exceptionTypes = {1: "EXC_BAD_ACCESS",
                    2: "EXC_BAD_INSTRUCTION",
                    3: "EXC_ARITHMETIC",
                    4: "EXC_EMULATION",
                    5: "EXC_SOFTWARE",
                    6: "EXC_BREAKPOINT",
                    7: "EXC_SYSCALL",
                    8: "EXC_MACH_SYSCALL",
                    9: "EXC_RPC_ALERT",
                    10: "EXC_CRASH",
                    11: "EXC_RESOURCE",
                    12: "EXC_GUARD",
                    13: "EXC_CORPSE_NOTIFY"}

# From sys/signal.h, as per https://developer.apple.com/documentation/metrickit/mxcrashdiagnostic/3552298-signal?language=objc
signalTypes = {1: "SIGHUP",
                2: "SIGINT", 
                3: "SIGQUIT",
                4: "SIGILL",
                5: "SIGTRAP",
                6: "SIGABRT",
                7: "SIGPOLL / SIGEMT",
                8: "SIGFPE",
                9: "SIGKILL",
                10: "SIGBUS",
                11: "SIGSEGV",
                12: "SIGSYS",
                13: "SIGPIPE",
                14: "SIGALRM",
                15: "SIGTERM",
                16: "SIGURG",
                17: "SIGSTOP",
                18: "SIGTSTP",
                19: "SIGCONT",
                20: "SIGCHLD",
                21: "SIGTTIN",
                22: "SIGTTOU",
                23: "SIGIO",
                24: "SIGXCPU",
                25: "SIGXFSZ",
                26: "SIGVTALRM",
                27: "SIGPROF",
                28: "SIGWINCH",
                29: "SIGINFO",
                30: "SIGUSR1",
                31: "SIGUSR2"}

LC_UUID = 0x1B

def _formatUuid(rawBytes):
    hexDigits = rawBytes.hex().upper()
    return "{0}-{1}-{2}-{3}-{4}".format(hexDigits[0:8], hexDigits[8:12], hexDigits[12:16], hexDigits[16:20], hexDigits[20:32])

def _sliceUuid(machoFile, sliceOffset):
    # Read the Mach-O header at this offset and scan its load commands for LC_UUID
    machoFile.seek(sliceOffset)
    header = machoFile.read(32)
    if len(header) < 28:
        return None

    magic = struct.unpack("<I", header[:4])[0]
    if magic in (0xFEEDFACF, 0xFEEDFACE):
        endian = "<"
    elif magic in (0xCFFAEDFE, 0xCEFAEDFE):
        endian = ">"
    else:
        return None

    is64Bit = struct.unpack(endian + "I", header[:4])[0] in (0xFEEDFACF, 0xCFFAEDFE)
    ncmds, sizeofcmds = struct.unpack(endian + "II", header[16:24])

    machoFile.seek(sliceOffset + (32 if is64Bit else 28))
    loadCommands = machoFile.read(sizeofcmds)

    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(loadCommands):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", loadCommands, pos)
        if cmd == LC_UUID and cmdsize >= 24:
            return _formatUuid(loadCommands[pos + 8:pos + 24])
        if cmdsize <= 0:
            break
        pos += cmdsize

    return None

binaryUuids = {}
def getBinaryUuids(path):
    # Reading LC_UUID out of the Mach-O header directly is ~70x faster than shelling out to
    # dwarfdump, and this gets called for every candidate symbols file we consider.
    global binaryUuids
    if path not in binaryUuids:
        uuids = []
        try:
            with open(path, "rb") as machoFile:
                magicBytes = machoFile.read(4)
                if len(magicBytes) < 4:
                    magic = 0
                else:
                    magic = struct.unpack(">I", magicBytes)[0]

                if magic in (0xCAFEBABE, 0xCAFEBABF):
                    # Fat binary: walk the arch table and collect a UUID per slice
                    isFat64 = magic == 0xCAFEBABF
                    archCount = struct.unpack(">I", machoFile.read(4))[0]
                    if archCount <= 64:
                        entrySize = 32 if isFat64 else 20
                        archTable = machoFile.read(entrySize * archCount)
                        for i in range(archCount):
                            entry = archTable[i * entrySize:(i + 1) * entrySize]
                            if len(entry) < entrySize:
                                break
                            if isFat64:
                                sliceOffset = struct.unpack(">Q", entry[8:16])[0]
                            else:
                                sliceOffset = struct.unpack(">I", entry[8:12])[0]
                            sliceUuid = _sliceUuid(machoFile, sliceOffset)
                            if sliceUuid:
                                uuids.append(sliceUuid)
                elif magic != 0:
                    sliceUuid = _sliceUuid(machoFile, 0)
                    if sliceUuid:
                        uuids.append(sliceUuid)
        except OSError:
            uuids = []

        binaryUuids[path] = uuids

    return binaryUuids[path]

def getDsymUuid(path):
    uuids = getBinaryUuids(path)
    return uuids[0] if uuids else ""

def binaryHasUuid(path, uuid):
    return uuid.upper() in getBinaryUuids(path)


deviceSupportPath = os.path.expanduser("~/Library/Developer/Xcode/iOS DeviceSupport/")

reportDeviceType = ""
reportOsBuild = ""
def noteDeviceHints(meta):
    # Remember which device/OS build the report came from so we can search that device's
    # symbol folder first instead of stat-ing our way through every folder we have.
    global reportDeviceType, reportOsBuild
    reportDeviceType = meta.get("deviceType", "")
    buildMatch = re.search(r"\(([^)]+)\)", meta.get("osVersion", ""))
    reportOsBuild = buildMatch.group(1) if buildMatch else ""

deviceFolders = None
def getDeviceFolders():
    global deviceFolders
    if deviceFolders is None:
        try:
            folders = [f for f in os.listdir(deviceSupportPath) if os.path.exists(deviceSupportPath + f + "/Symbols/")]
        except OSError:
            folders = []

        folders.sort(key=lambda f: (0 if reportOsBuild and reportOsBuild in f else 1,
                                    0 if reportDeviceType and f.startswith(reportDeviceType) else 1))
        deviceFolders = folders

    return deviceFolders

symbolFiles = {}
def getSymbolFile(originBinaryName, uuid):
    startPath = deviceSupportPath
    global symbolFiles

    key = f"{originBinaryName}.{uuid}"
    if not key in symbolFiles:
        # Walk through all the device folders and look for a symbol file for this binary name that matches this UUID

        foundPath = ""
        for deviceFolder in getDeviceFolders():
            systemLibPath = startPath + deviceFolder + "/Symbols/"

            if originBinaryName == binaryName:
                # If the binary name is the one we specified the symbols path for, use that
                foundPath = symbolsFilePath
            elif originBinaryName.startswith("libswift"):
                # Swift-related symbol files are in their own folder
                foundPath = systemLibPath + "usr/lib/swift/" + originBinaryName
            elif originBinaryName.startswith("lib") and originBinaryName.endswith(".dylib"):
                # A binary name like libsystem_kernel.dylib is going to be in <device folder>/usr/lib/system
                foundPath = systemLibPath + "usr/lib/system/" + originBinaryName
                if not os.path.exists(foundPath):
                    foundPath = systemLibPath + "usr/lib/" + originBinaryName

                if originBinaryName in ["libFontParser.dylib", "libGSFont.dylib", "libGSFontCache.dylib", "libType1Scaler.dylib", "libhvf.dylib"]:
                    foundPath = systemLibPath + "System/Library/PrivateFrameworks/FontServices.framework/" + originBinaryName
            elif originBinaryName == "dyld":
                foundPath = systemLibPath + "usr/lib/dyld"
            else:
                # Other binary names like Foundation or UIKitCore are going to be either in <device folder>/System/Library/Frameworks or <device folder>/System/Library/PrivateFrameworks
                foundPath = systemLibPath + "System/Library/Frameworks/{0}.framework/{0}".format(originBinaryName)

                if not os.path.exists(foundPath):
                    foundPath = systemLibPath + f"System/Library/Frameworks/{originBinaryName}.framework/Versions/A/{originBinaryName}"

                if not os.path.exists(foundPath):
                    foundPath = systemLibPath + "System/Library/PrivateFrameworks/{0}.framework/{0}".format(originBinaryName)
                
                if not os.path.exists(foundPath):
                    foundPath = systemLibPath + f"System/Library/AccessibilityBundles/{originBinaryName}.axbundle/{originBinaryName}"

                if not os.path.exists(foundPath):
                    foundPath = systemLibPath + f"System/Library/AccessibilityBundles/{originBinaryName}.bundle/{originBinaryName}"

            if len(foundPath) > 0 and os.path.exists(foundPath) and binaryHasUuid(foundPath, uuid):
                symbolFiles[key] = foundPath
                break

        if key not in symbolFiles:
            symbolFiles[key] = ""

    return symbolFiles[key]

atosResults = {}
def runAtos(dsymPath, offsets):
    # atos reads addresses from stdin in interactive mode and separates each result with a blank
    # line, so one invocation can do a whole binary's worth of frames.
    stdin = "".join(hex(offset) + "\n" for offset in offsets)
    atosOutput = subprocess.run(["atos", "-i", "-arch", "arm64e", "-o", dsymPath, "--offset"],
                                input=stdin.encode("utf-8"), stdout=subprocess.PIPE).stdout.decode("utf-8")

    blocks = atosOutput.split("\n\n")
    while blocks and blocks[-1].strip() == "":
        blocks.pop()

    if len(blocks) != len(offsets):
        # Couldn't line results up with the addresses we sent; caller falls back to one at a time
        return None

    return [block.strip().replace("\n", " <newline> ") for block in blocks]

def symbolicate(dsymPath, offset):
    key = (dsymPath, offset)
    if key not in atosResults:
        # This is based on this forum post: https://developer.apple.com/forums/thread/681967
        atosOutput = subprocess.run(["atos", "-i", "-arch", "arm64e", "-o", dsymPath, "--offset", hex(offset)], stdout=subprocess.PIPE).stdout.decode("utf-8")
        atosResults[key] = atosOutput.strip().replace("\n", " <newline> ")

    return atosResults[key]

def collectFrameOffsets(root, offsetsByPath):
    offset = root["offsetIntoBinaryTextSegment"] if "offsetIntoBinaryTextSegment" in root else None
    originBinaryName = root["binaryName"] if "binaryName" in root else None
    originUuid = root["binaryUUID"] if "binaryUUID" in root else None

    if offset and originBinaryName and originUuid:
        dsymPath = getSymbolFile(originBinaryName, originUuid)
        if len(dsymPath) > 0 and (dsymPath, offset) not in atosResults:
            offsetsByPath.setdefault(dsymPath, set()).add(offset)

    if "subFrames" in root:
        for sub in root["subFrames"]:
            collectFrameOffsets(sub, offsetsByPath)

def prewarmSymbols(callstackTree):
    # Resolve every frame in the report up front, grouped by binary, so printFrame only has to
    # look results up. Also collapses the many frames that repeat across threads.
    offsetsByPath = {}
    for stack in callstackTree["callStacks"]:
        for root in stack["callStackRootFrames"]:
            collectFrameOffsets(root, offsetsByPath)

    for dsymPath, offsetSet in offsetsByPath.items():
        offsets = sorted(offsetSet)
        symbols = runAtos(dsymPath, offsets)
        if symbols is None:
            for offset in offsets:
                symbolicate(dsymPath, offset)
        else:
            for offset, symbol in zip(offsets, symbols):
                atosResults[(dsymPath, offset)] = symbol

result = ""
def printResultLine(ln):
    global result
    result += ln + "\n"
    print(ln)

# Pass 0 for level to format the call stack as indented like a spindump, or -1 to print like a crash stack
def printFrame(root, level=-1):
    offset = root["offsetIntoBinaryTextSegment"] if "offsetIntoBinaryTextSegment" in root else None
    originBinaryName = root["binaryName"] if "binaryName" in root else None
    originUuid = root["binaryUUID"] if "binaryUUID" in root else None
    sampleCount = 0
    if "sampleCount" in root:
        sampleCount = root["sampleCount"]

    spacer = "|  "
    indentPrefix = spacer * level if level >= 0 else ""

    if not offset or not originBinaryName or not originUuid:
        printResultLine(f"{indentPrefix}<missing information in frame>")
        return

    dsymPath = getSymbolFile(originBinaryName, originUuid)
    
    processedLine = False
    errorReason = ""
    
    if len(dsymPath) > 0:
        atosResult = symbolicate(dsymPath, offset)
        if level >= 0:
            # This is a cpu or disk write diagnostic. Print it sort of like how spindumps are formatted.
            printResultLine("{0}{1}: {2}".format(indentPrefix, sampleCount, atosResult))
        else:
            # Crash diagnostic or otherwise
            printResultLine(atosResult)
        processedLine = True
    else:
        errorReason = f"symbols file not found for '{originBinaryName}'"

    if processedLine == False:
        printResultLine(f"{indentPrefix}<WARNING, {errorReason}> {originBinaryName} ({offset})")

    if "subFrames" in root:
        frames = root["subFrames"]
        if level >= 0:
            level = level + 1
        for sub in frames:
            printFrame(sub, level=level)


forceHierarchical = False
def printCallstack(callstackTree):
    index = 0

    # The callStackPerThread property indicates whether each object in callStackRootFrames can be relied on to have one linear call stack.
    # When this property is false, it means this is a report like a spindump, where it's going to show multiple stacks at a time with sample counts.
    # In that case we format it like a spindump, with each line indented further than the last one, to make the hierarchy clear.
    simpleCallStack = callstackTree["callStackPerThread"] if "callStackPerThread" in callstackTree else False
    global forceHierarchical
    if forceHierarchical:
        simpleCallStack = False

    prewarmSymbols(callstackTree)

    for stack in callstackTree["callStacks"]:
        rootFrames = stack["callStackRootFrames"]

        # The threadAttributed property indicates whether this is the thread that is "attributed" (crashed in a crash diagnostic)
        crashed = stack["threadAttributed"] if "threadAttributed" in stack else False

        for root in rootFrames:
            printResultLine('{0}Call stack {1}:'.format("Attributed: " if crashed else "", index))
            printFrame(root, level=-1 if simpleCallStack else 0)
            printResultLine("")
            index += 1

def processCrashDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    excType = meta["exceptionType"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    excCode = meta["exceptionCode"]
    signal = meta["signal"]

    printResultLine("Symbolicating crash report from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))

    exceptionTypeName = "unknown"
    if excType in exceptionTypes:
        exceptionTypeName = exceptionTypes[excType]

    printResultLine("Exception type: {0}, {1}".format(excType, exceptionTypeName))
    printResultLine("Exception code: {0}".format(excCode))

    if "terminationReason" in meta:
        print(f"Termination Reason: {meta["terminationReason"]}")

    signalName = "unknown"
    if signal in signalTypes:
        signalName = signalTypes[signal]

    printResultLine("Signal: {0}, {1}".format(signal, signalName))
    printResultLine("")

    callstackTree = diag["callStackTree"]
    printCallstack(callstackTree)

def processDiskDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    writes = meta["writesCaused"]

    printResultLine("Symbolicating disk write exception diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    printResultLine("Writes caused: {0}".format(writes))
    printResultLine("")

    callStack = diag["callStackTree"]
    printCallstack(callStack)

def processCpuDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    totalTime = meta["totalCPUTime"]
    sampledTime = meta["totalSampledTime"]

    printResultLine("Symbolicating CPU exception diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    printResultLine("Total time: {0} of {1}".format(totalTime, sampledTime))
    printResultLine("")

    callStack = diag["callStackTree"]
    printCallstack(callStack)

def processAppLaunchDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    duration = meta["launchDuration"]

    #App launch diagnostics should be formatted like spindumps, but the callStackPerThread value is true, seemingly wrongly
    global forceHierarchical
    forceHierarchical = True

    printResultLine("Symbolicating app launch diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    printResultLine(f"Launch duration: {duration}")
    printResultLine("")

    callStack = diag["callStackTree"]
    printCallstack(callStack)




parser = argparse.ArgumentParser()
parser.add_argument("--report-path", help="Path to MetricKit diagnostic report")
parser.add_argument("--symbols-path", help="Path to symbols file, either xcarchive or dSYM")
parser.add_argument("--binary-name", help="Binary name. Pulled from the file name of the symbols path if not specified.")

args = parser.parse_args()

if not args.report_path or not args.symbols_path:
    printResultLine("Report path and symbols path are required.")
    exit(1)

jsonPath = args.report_path
symbolsFilePath = args.symbols_path

printResultLine(f"Processing input file: {jsonPath}")

binaryName = ""
if args.binary_name:
    binaryName = args.binary_name
else:
    symbolFileName = symbolsFilePath.split("/")[-1]
    binaryName = symbolFileName.split(".")[0]

if symbolsFilePath.endswith(".xcarchive"):
    symbolsFilePath = "{0}/dSYMs/{1}.app.dSYM/Contents/Resources/DWARF/{1}".format(symbolsFilePath, binaryName)
    
printResultLine("Binary name: {0}".format(binaryName))

if not os.path.exists(symbolsFilePath):
    printResultLine("Symbols file path '{0}' does not exist".format(symbolsFilePath))
    exit(0)

printResultLine("UUID of specified symbols file is {0}".format(getDsymUuid(symbolsFilePath)))

with open(jsonPath, 'r') as jsonFile:
    jsonData = json.loads(jsonFile.read())

    custId = jsonData.get("customer_id")
    timestamp = jsonData.get("timestamp")
    osVersion = jsonData.get("os_version")
    deviceType = jsonData.get("device_model")
    appVersion = jsonData.get("app_version")

    if custId and timestamp and osVersion and deviceType and appVersion:
        reportDate = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()

        printResultLine("Customer ID: {0}".format(custId))
        printResultLine("Date of report on device: {0}".format(reportDate))
        printResultLine("Device: {0}, {1}".format(deviceType, osVersion))
        printResultLine(f"App version: {appVersion}")
        printResultLine("")

    payload = jsonData.get("payload") or jsonData

    if "crashDiagnostics" in payload:
        crashDiags = payload["crashDiagnostics"]
        if len(crashDiags) != 1:
            printResultLine("More than one crashDiagnostics entry!")
        for diag in crashDiags:
            processCrashDiagnostic(diag)

    if "diskWriteExceptionDiagnostics" in payload:
        diskDiags = payload["diskWriteExceptionDiagnostics"]
        for diag in diskDiags:
            processDiskDiagnostic(diag)

    if "cpuExceptionDiagnostics" in payload:
        cpuDiags = payload["cpuExceptionDiagnostics"]
        for diag in cpuDiags:
            processCpuDiagnostic(diag)

    if "appLaunchDiagnostics" in payload:
        launchDiags = payload["appLaunchDiagnostics"]
        for diag in launchDiags:
            processAppLaunchDiagnostic(diag)
    
    inputFileName = jsonPath.split('/')[-1]
    outputFileName = inputFileName.replace(".json", "_processed.txt")
    outputPath = jsonPath.replace(inputFileName, outputFileName)
    print(f"Writing output to {outputPath}")
    with open(outputPath, 'w') as outputFile:
        outputFile.write(result)
