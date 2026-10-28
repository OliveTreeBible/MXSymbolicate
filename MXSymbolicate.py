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
reportArch = ""
def noteDeviceHints(meta):
    # Remember which device/OS build the report came from so we can search that device's
    # symbol folder first instead of stat-ing our way through every folder we have.
    global reportDeviceType, reportOsBuild, reportArch
    reportDeviceType = meta.get("deviceType", "")
    reportArch = meta.get("platformArchitecture", "")
    buildMatch = re.search(r"\(([^)]+)\)", meta.get("osVersion", ""))
    reportOsBuild = buildMatch.group(1) if buildMatch else ""

deviceFolders = None
def getDeviceFolders():
    # Returns the Symbols folder to search for each device folder. Older iOS versions keep it at
    # <device folder>/Symbols/; iOS 27 puts it under an architecture folder: <device folder>/arm64e/Symbols/
    global deviceFolders
    if deviceFolders is None:
        folders = []
        try:
            for f in os.listdir(deviceSupportPath):
                candidates = [deviceSupportPath + f + "/Symbols/"]
                archFolder = atosArch()
                for arch in [reportArch, archFolder]:
                    if arch:
                        candidates.append(deviceSupportPath + f + "/" + arch + "/Symbols/")
                for candidate in candidates:
                    if os.path.exists(candidate):
                        folders.append((f, candidate))
                        break
        except OSError:
            folders = []

        folders.sort(key=lambda entry: (0 if reportOsBuild and reportOsBuild in entry[0] else 1,
                                        0 if reportDeviceType and entry[0].startswith(reportDeviceType) else 1))
        deviceFolders = [symbolsPath for _, symbolsPath in folders]

    return deviceFolders

symbolFiles = {}
def getSymbolFile(originBinaryName, uuid):
    global symbolFiles

    key = f"{originBinaryName}.{uuid}"
    if not key in symbolFiles:
        # Walk through all the device folders and look for a symbol file for this binary name that matches this UUID

        foundPath = ""
        if originBinaryName == binaryName and os.path.exists(symbolsFilePath) and binaryHasUuid(symbolsFilePath, uuid):
            # The app's own binary doesn't live in any device folder, so check the specified symbols file first
            symbolFiles[key] = symbolsFilePath

        for systemLibPath in ([] if key in symbolFiles else getDeviceFolders()):

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

def atosArch():
    # Reports can say "arm64e.x1"; atos only knows the base architecture name
    return reportArch.split(".")[0] if reportArch else "arm64e"

atosResults = {}
def runAtos(dsymPath, offsets):
    # atos reads addresses from stdin in interactive mode and separates each result with a blank
    # line, so one invocation can do a whole binary's worth of frames.
    stdin = "".join(hex(offset) + "\n" for offset in offsets)
    atosOutput = subprocess.run(["atos", "-i", "-arch", atosArch(), "-o", dsymPath, "--offset"],
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
        atosOutput = subprocess.run(["atos", "-i", "-arch", atosArch(), "-o", dsymPath, "--offset", hex(offset)], stdout=subprocess.PIPE).stdout.decode("utf-8")
        atosResults[key] = atosOutput.strip().replace("\n", " <newline> ")

    return atosResults[key]

# Version 2 reports don't put binaryName on each frame; they list {name, uuid} pairs once per call stack tree
binaryNamesByUuid = {}
def frameBinaryName(root):
    if "binaryName" in root:
        return root["binaryName"]
    return binaryNamesByUuid.get(root.get("binaryUUID"))

def collectFrameOffsets(root, offsetsByPath):
    offset = root["offsetIntoBinaryTextSegment"] if "offsetIntoBinaryTextSegment" in root else None
    originBinaryName = frameBinaryName(root)
    originUuid = root["binaryUUID"] if "binaryUUID" in root else None

    if offset and originBinaryName and originUuid:
        dsymPath = getSymbolFile(originBinaryName, originUuid)
        if len(dsymPath) > 0 and (dsymPath, offset) not in atosResults:
            offsetsByPath.setdefault(dsymPath, set()).add(offset)

    if "subFrames" in root:
        for sub in root["subFrames"]:
            collectFrameOffsets(sub, offsetsByPath)

def callStackEntries(callstackTree):
    # Version 1 reports use callStacks/callStackRootFrames, version 2 uses callStackThreads/rootFrames
    for stack in callstackTree.get("callStacks") or callstackTree.get("callStackThreads") or []:
        yield stack, stack.get("callStackRootFrames") or stack.get("rootFrames") or []

def prewarmSymbols(callstackTree):
    # Resolve every frame in the report up front, grouped by binary, so printFrame only has to
    # look results up. Also collapses the many frames that repeat across threads.
    offsetsByPath = {}
    for stack, rootFrames in callStackEntries(callstackTree):
        for root in rootFrames:
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
    originBinaryName = frameBinaryName(root)
    originUuid = root["binaryUUID"] if "binaryUUID" in root else None
    sampleCount = 0
    if "sampleCount" in root:
        sampleCount = root["sampleCount"]

    spacer = "|  "
    indentPrefix = spacer * level if level >= 0 else ""

    if not offset or not originUuid:
        printResultLine(f"{indentPrefix}<missing information in frame>")
        return

    if not originBinaryName:
        # Typically a kernel or kext frame; the UUID is all we have to identify the binary
        printResultLine(f"{indentPrefix}<WARNING, unnamed binary {originUuid}> ({offset})")
        printSubFrames(root, level)
        return

    dsymPath = getSymbolFile(originBinaryName, originUuid)
    
    processedLine = False
    errorReason = ""
    
    if len(dsymPath) > 0:
        atosResult = symbolicate(dsymPath, offset)
        if len(atosResult) == 0:
            # atos found the binary but had no symbol for this offset
            atosResult = f"<no symbol> {originBinaryName} ({offset})"
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

    printSubFrames(root, level)

def printSubFrames(root, level):
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

    global binaryNamesByUuid
    binaryNamesByUuid = {b["uuid"]: b["name"] for b in callstackTree.get("binaryInfo", []) if "uuid" in b and "name" in b}

    prewarmSymbols(callstackTree)

    for stack, rootFrames in callStackEntries(callstackTree):

        # The threadAttributed property indicates whether this is the thread that is "attributed" (crashed in a crash diagnostic)
        crashed = stack["threadAttributed"] if "threadAttributed" in stack else False

        for root in rootFrames:
            printResultLine('{0}Call stack {1}:'.format("Attributed: " if crashed else "", index))
            printFrame(root, level=-1 if simpleCallStack else 0)
            printResultLine("")
            index += 1

def formatQuantity(value):
    # Version 2 reports give measurements as {"unit": "ms", "value": 1014.2}
    if isinstance(value, dict) and "value" in value:
        number = value["value"]
        if isinstance(number, float):
            number = round(number, 1)
        return "{0} {1}".format(number, value.get("unit", "")).strip()
    return value

def isVersion2Payload(payload):
    # Version 1 payloads have no top-level version (each diagnostic carries its own); version 2 ones say "2.0.0"
    version = str(payload.get("version", "")).split(".")[0]
    return version.isdigit() and int(version) >= 2

def metaFromVersion2(env, diag):
    # Rebuild the diagnosticMetaData dict that version 1 reports have, so the process* functions below can handle both.
    # In version 2 the device/app info lives once in payload.environment, and the diagnostic only holds its own fields.
    osInfo = env.get("osVersion", {})
    osString = "unknown"
    if isinstance(osInfo, dict) and osInfo.get("number"):
        osString = "{0} {1} ({2})".format(osInfo.get("platform", ""), osInfo["number"], osInfo.get("buildNumber", ""))

    meta = {"bundleIdentifier": env.get("bundleIdentifier", "unknown"),
            "appVersion": env.get("applicationVersion", "unknown"),
            "appBuildVersion": env.get("applicationBuildVersion", "unknown"),
            "deviceType": env.get("deviceType", ""),
            "osVersion": osString,
            "platformArchitecture": env.get("platformArchitecture", ""),
            "pid": env.get("pid")}

    renamedKeys = {"exceptionReason": "objectiveCexceptionReason", "totalBytesWritten": "writesCaused"}
    for key, value in diag.items():
        if key != "callStackTree":
            meta[renamedKeys.get(key, key)] = value

    return {"diagnosticMetaData": meta, "callStackTree": diag["callStackTree"]}

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
        printResultLine("Termination Reason: {0}".format(meta["terminationReason"]))

    if "terminationCategory" in meta:
        printResultLine("Termination Category: {0}".format(meta["terminationCategory"]))

    if "objectiveCexceptionReason" in meta:
        objcReason = meta["objectiveCexceptionReason"]
        printResultLine("Objective-C exception: {0}".format(objcReason.get("exceptionName", "unknown")))
        if "composedMessage" in objcReason:
            printResultLine("Exception message: {0}".format(objcReason["composedMessage"]))

    signalName = "unknown"
    if signal in signalTypes:
        signalName = signalTypes[signal]

    printResultLine("Signal: {0}, {1}".format(signal, signalName))

    if "virtualMemoryRegionInfo" in meta:
        printResultLine("Virtual memory region info:")
        printResultLine(meta["virtualMemoryRegionInfo"])

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
    writes = formatQuantity(meta["writesCaused"])

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
    totalTime = formatQuantity(meta["totalCPUTime"])
    sampledTime = formatQuantity(meta["totalSampledTime"])

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
    duration = formatQuantity(meta["launchDuration"])

    #App launch diagnostics should be formatted like spindumps, but the callStackPerThread value is true, seemingly wrongly
    global forceHierarchical
    forceHierarchical = True

    printResultLine("Symbolicating app launch diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    printResultLine(f"Launch duration: {duration}")
    printResultLine("")

    callStack = diag["callStackTree"]
    printCallstack(callStack)

def processHangDiagnostic(diag):
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]
    duration = formatQuantity(meta["hangDuration"])

    # Hangs sample the main thread over time, so format them like spindumps, as with app launch
    global forceHierarchical
    forceHierarchical = True

    printResultLine("Symbolicating hang diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
    printResultLine(f"Hang duration: {duration}")
    printResultLine("")

    callStack = diag["callStackTree"]
    printCallstack(callStack)

def processMemoryDiagnostic(diag):
    # Memory exception diagnostics (version 2 only) carry nothing but call stacks
    meta = diag["diagnosticMetaData"]
    noteDeviceHints(meta)
    bundleId = meta["bundleIdentifier"]
    appVersion = meta["appVersion"]
    appBuildVersion = meta["appBuildVersion"]

    printResultLine("Symbolicating memory exception diagnostic from {0} {1}.{2}".format(bundleId, appVersion, appBuildVersion))
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
    # The binary can be the app itself or an extension (widget, intent, etc.), which have different dSYM names
    archivePath = symbolsFilePath
    symbolsFilePath = "{0}/dSYMs/{1}.app.dSYM/Contents/Resources/DWARF/{1}".format(archivePath, binaryName)
    if not os.path.exists(symbolsFilePath):
        symbolsFilePath = "{0}/dSYMs/{1}.appex.dSYM/Contents/Resources/DWARF/{1}".format(archivePath, binaryName)

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

    if isVersion2Payload(payload):
        # Each diagnostic type is a single object here, rather than a list. The order matters: hang and launch
        # diagnostics switch call stack formatting to hierarchical, so they go after the others.
        environment = payload.get("environment", {})
        versionTwoHandlers = [("crashDiagnostic", processCrashDiagnostic),
                              ("diskWriteExceptionDiagnostic", processDiskDiagnostic),
                              ("cpuExceptionDiagnostic", processCpuDiagnostic),
                              ("memoryExceptionDiagnostic", processMemoryDiagnostic),
                              ("appLaunchDiagnostic", processAppLaunchDiagnostic),
                              ("hangDiagnostic", processHangDiagnostic)]
        for key, handler in versionTwoHandlers:
            if key in payload:
                handler(metaFromVersion2(environment, payload[key]))

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

    if "hangDiagnostics" in payload:
        hangDiags = payload["hangDiagnostics"]
        for diag in hangDiags:
            processHangDiagnostic(diag)

    inputFileName = jsonPath.split('/')[-1]
    outputFileName = inputFileName.replace(".json", "_processed.txt")
    outputPath = jsonPath.replace(inputFileName, outputFileName)
    print(f"Writing output to {outputPath}")
    with open(outputPath, 'w') as outputFile:
        outputFile.write(result)
