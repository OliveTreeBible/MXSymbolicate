#!/usr/bin/env python3
import json
import os, sys
import subprocess
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

parser = argparse.ArgumentParser()
parser.add_argument("--report-path", help="Path to MetricKit diagnostic report")
parser.add_argument("--symbols-path", help="Path to symbols file, either xcarchive or dSYM")
parser.add_argument("--binary-name", help="Binary name. Pulled from the file name of the symbols path if not specified.")

args = parser.parse_args()

if not args.report_path or not args.symbols_path:
    print("Report path and symbols path are required.")
    exit(1)

jsonPath = args.report_path
symbolsFilePath = args.symbols_path

binaryName = ""
if args.binary_name:
    binaryName = args.binary_name
else:
    symbolFileName = symbolsFilePath.split("/")[-1]
    binaryName = symbolFileName.split(".")[0]

if symbolsFilePath.endswith(".xcarchive"):
    symbolsFilePath = "{0}/dSYMs/{1}.app.dSYM/Contents/Resources/DWARF/{1}".format(symbolsFilePath, binaryName)
    
print("Binary name: {0}".format(binaryName))

if not os.path.exists(symbolsFilePath):
    print("dSYM path '{0}' does not exist".format(symbolsFilePath))
    exit(0)

def getDsymUuid(path):
    uuidResultLine = subprocess.run(["dwarfdump", "--uuid", path], stdout=subprocess.PIPE).stdout.decode("utf-8")
    dsymUuid = re.search("UUID: ([0-9A-Za-z\-]+?) \(.+", uuidResultLine).group(1)
    return dsymUuid

print("UUID of specified dSYM is {0}".format(getDsymUuid(symbolsFilePath)))

systemLibPath = ""

# Pass 0 for level to format the call stack as indented like a spindump, or -1 to print like a crash stack
def printFrame(root, level=-1):
    offset = root["offsetIntoBinaryTextSegment"]
    originBinaryName = root["binaryName"]
    originUuid = root["binaryUUID"]
    sampleCount = 0
    if "sampleCount" in root:
        sampleCount = root["sampleCount"]

    dsymPath = ""
    architecture = "arm64e"
    if originBinaryName == binaryName:
        # If the binary name is the one we specified the symbols path for, use that
        dsymPath = symbolsFilePath
        architecture = "arm64"
    elif originBinaryName.startswith("lib") and originBinaryName.endswith(".dylib"):
        # A binary name like libsystem_kernel.dylib is going to be in <device folder>/usr/lib/system
        dsymPath = systemLibPath + "usr/lib/system/" + originBinaryName
    else:
        # Other binary names like Foundation or UIKitCore are going to be either in <device folder>/System/Library/Frameworks or <device folder>/System/Library/PrivateFrameworks
        dsymPath = systemLibPath + "System/Library/Frameworks/{0}.framework/{0}".format(originBinaryName)
        if not os.path.exists(dsymPath):
            dsymPath = systemLibPath + "System/Library/PrivateFrameworks/{0}.framework/{0}".format(originBinaryName)

    processedLine = False
    spacer = "|  "
    indentPrefix = spacer * level if level >= 0 else ""
    
    if os.path.exists(dsymPath):
        dsymUuid = getDsymUuid(dsymPath)
        if originUuid == dsymUuid:
            # This is based on this forum post: https://developer.apple.com/forums/thread/681967
            atosResult = subprocess.run(["atos", "-arch", architecture, "-o", dsymPath, "-l", "0x1", hex(offset)], stdout=subprocess.PIPE).stdout.decode("utf-8").strip()
            if level >= 0:
                # This is a cpu or disk write diagnostic. Print it sort of like how spindumps are formatted.
                print("{0}{1}: {2}".format(indentPrefix, sampleCount, atosResult))
            else:
                # Crash diagnostic or otherwise
                print(atosResult)
            processedLine = True
        else:
            print("--Warning: UUID of {1} ({2}) does not match expected {3} for {4}".format(dsymPath, dsymUuid, originUuid, originBinaryName))
    
    if processedLine == False:
        print("{0}{1} ({2})".format(indentPrefix, originBinaryName, offset))

    if "subFrames" in root:
        frames = root["subFrames"]
        if level >= 0:
            level = level + 1
        for sub in frames:
            printFrame(sub, level=level)


def printCallstack(callstackTree):
    index = 0

    # The callStackPerThread property indicates whether each object in callStackRootFrames can be relied on to have one linear call stack.
    # When this property is false, it means this is a report like a spindump, where it's going to show multiple stacks at a time with sample counts.
    # In that case we format it like a spindump, with each line indented further than the last one, to make the hierarchy clear.
    simpleCallStack = callstackTree["callStackPerThread"] if "callStackPerThread" in callstackTree else False
    for stack in callstackTree["callStacks"]:
        rootFrames = stack["callStackRootFrames"]

        # The threadAttributed property indicates whether this is the thread that crashed, in a crash diagnostic
        crashed = stack["threadAttributed"] if "threadAttributed" in stack else False

        for root in rootFrames:
            print('{0}Call stack {1}:'.format("Crashed: " if crashed else "", index))
            printFrame(root, level=-1 if simpleCallStack else 0)
            print("")
            index += 1

def processCrashDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    bundleId = meta["bundleIdentifier"]
    excType = meta["exceptionType"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    excCode = meta["exceptionCode"]
    signal = meta["signal"]

    print("Symbolicating crash report from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))

    exceptionTypeName = "unknown"
    if excType in exceptionTypes:
        exceptionTypeName = exceptionTypes[excType]

    print("Exception type: {0}, {1}".format(excType, exceptionTypeName))
    print("Exception code: {0}".format(excCode))

    signalName = "unknown"
    if signal in signalTypes:
        signalName = signalTypes[signal]

    print("Signal: {0}, {1}".format(signal, signalName))
    print("")

    callstackTree = diag["callStackTree"]
    printCallstack(callstackTree)

def processDiskDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    writes = meta["writesCaused"]

    print("Symbolicating disk write exception diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    print("Writes caused: {0}".format(writes))

    callStack = diag["callStackTree"]
    printCallstack(callStack)

def processCpuDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    osVersion = meta["osVersion"]
    totalTime = meta["totalCPUTime"]
    sampledTime = meta["totalSampledTime"]

    print("Symbolicating CPU exception diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    print("Total time: {0} of {1}".format(totalTime, sampledTime))

    callStack = diag["callStackTree"]
    printCallstack(callStack)

with open(jsonPath, 'r') as jsonFile:
    jsonData = json.loads(jsonFile.read())

    custId = jsonData["customer_id"]
    timestamp = jsonData["timestamp"]
    osVersion = jsonData["os_version"]
    deviceType = jsonData["device_model"]
    reportDate = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()

    print("Customer ID: {0}".format(custId))
    print("Date of report on device: {0}".format(reportDate))
    print("Device: {0}, {1}".format(deviceType, osVersion))
    
    # Find the folder containing system libraries for this OS version.
    # Folder names here for modern iOS versions are formatted like `<device model> <OS version> <OS build>`
    # For example: `iPad13,16 17.1 (21B5045h)`
    # So we look for a folder containing the OS version from the report
    startPath = "~/Library/Developer/Xcode/iOS DeviceSupport/"
    startPath = os.path.expanduser(startPath)
    for deviceFolder in os.listdir(startPath):
        if osVersion in deviceFolder:
            systemLibPath = startPath + deviceFolder + "/Symbols/"
            print("Found system library path for {0}: {1}".format(osVersion, systemLibPath))
            break

    if len(systemLibPath) == 0:
        print("Warning: failed to find system library path for {0}".format(osVersion))
        
    print("")

    payload = jsonData["payload"]

    if "crashDiagnostics" in payload:
        crashDiags = payload["crashDiagnostics"]
        if len(crashDiags) != 1:
            print("More than one crashDiagnostics entry!")
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
    

