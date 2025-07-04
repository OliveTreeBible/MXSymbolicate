# MXSymbolicate

`MXSymbolicate.py` is an example python script for symbolicating call stacks in json-formatted diagnostic reports produced by [MetricKit](https://developer.apple.com/documentation/metrickit).

It's specifically written to deal with the diagnostic reports as saved by the [Olive Tree Bible App](https://apps.apple.com/us/app/bible-app-read-study-daily/id332615624), in which iOS report json is embedded in a `payload` field in the root object with some other properties, like so:

```
{
    "customer_id": "...",
    "timestamp": "...",
    "os_version": "...",
    "device_model": "...",
    "app_version": "...",
    "payload": {
        ...MetricKit payload here...
    }
}
```

However, it is also compatible with the "raw"  [`jsonRepresentation`](https://developer.apple.com/documentation/metrickit/mxdiagnosticpayload/3552307-jsonrepresentation) property of `MXDiagnosticPayload` for crash reports from other apps.

Caveat emptor: I am not an experienced Python developer, so I'm sure there are lots of things about this script that could be done differently. :-)

## Usage

The simplest usage is to give a report path and symbols file path:
```
./MXSymbolicate.py --report-path diagnosticReport.json --symbols-path /path/to/app.dSYM/Contents/Resources/DWARF/app
```

There's also an optional `--binary-name` argument if the binary name of the app is not the same as the file name of the symbols file:

```
./MXSymbolicate.py --report-path diagnosticReport.json --symbols-path /path/to/app.dSYM/Contents/Resources/DWARF/app --binary-name MyApp
```

The `--symbols-path` can also be a path to an `xcarchive` file, in which case the script will drill down to find the symbols file:

```
./MXSymbolicate.py --report-path diagnosticReport.json --symbols-path /path/to/MyApp.xcarchive
```

In that example, the binary name will be taken as `MyApp`, and it'll look for a dSYM at `/path/to/MyApp.xcarchive/dSYMs/MyApp.app.dSYM/Contents/Resources/DWARF/MyApp`.

When called in any of these ways, the script will print some metadata from the report and the symbolicated call stacks. Call stacks in crash diagnostics will be printed linearly, like you'd see in a normal crash report. If the `callStackPerThread` property is `false`, though, the call stack is showing the heaviest traces, and it's not a simple linear stack, so the script prints it like a `spindump`. Note that app launch diagnostics currently have `callStackPerThread` set false even though they need to be printed `spindump`-style; this is a bug, as per some awesome engineers I was able to talk to in WWDC 2024 labs (FB13889418).

## Symbolicating frames in system libraries

`MXSymbolicate` uses the dSYM provided to it via `--symbols-path` to symbolicate call stack frames in the source app. But it needs separate dSYM files for system libraries like `UIKit` and `libsystem_kernel.dylib`. As it turns out, these are available for any iOS version that's been on a device you've connected to Xcode in `~/Library/Developer/Xcode/iOS DeviceSupport`.

Via trial and error, I've figured out that in this `iOS DeviceSupport/<device>/Symbols` folder:

 - Some font-related libraries are in `System/Library/PrivateFrameworks/FontServices.framework`
 - Binaries with names like `libsystem_kernel.dylib` and `libsystem_pthread.dylib` (beginning with `lib` and ending with `.dylib`) are in `usr/lib/system/<name>` or `usr/lib/<name`
 - Binaries beginning with `libswift` are in `user/lib/swift`
 - `dyld` is at `usr/lib/dyld`
 - Other names like `UIKitCore` and `Foundation` are in one of:
   - `System/Library/Frameworks/<name>.framework/<name>`
   - `System/Library/Frameworks/<name>.framework/Versions/A/<name>`
   - `System/Library/PrivateFrameworks/<name>.framework/<name>`
   - `System/Library/AccessibilityBundles/<name>.axbundle/<name>`
   - `System/Library/AccessibilityBundles/<name>.bundle/<name>`

Binaries that I haven't found anywhere:
 - `GAXClient`

The script walks through those folders and looks for symbol files for system frameworks using the above rules that match the UUID in the call stack frame.

I imagine there are some frameworks that don't follow those rules, or situations in which those rules don't work - I'll figure that out if and when I run into them in a crash report.

## Useful Resources

When I wrote this script, there was a surprising lack of documentation on how exactly to use the information in the diagnostic reports. But here's what I used to figure out how to get this far:

 - Documentation on the [`jsonRepresentation`](https://developer.apple.com/documentation/metrickit/mxcallstacktree/jsonrepresentation()) property of `MXCallStackTree` explaining all the properties
 - Introduction of MetricKit at WWDC 2019: [Improving Battery Life and Performance](https://developer.apple.com/videos/play/wwdc2019/417/)
 - WWDC 2020: [What's New in MetricKit](https://developer.apple.com/videos/play/wwdc2020/10081/)
 - [Apple documentation on symbolicating](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report)
 - [Apple Developer Forum thread](https://developer.apple.com/forums/thread/681967) on how to plug the values in the call stack tree into `atos`
 - [Where to find system framework dSYM files](https://www.finik.net/2017/03/20/iOS-Crash-Symbolication-for-dummies-Part-2/)

## Useful tidbits

 - Sometimes the UUID of a system framework can vary more granularly than the iOS version. For example, you might get two crash reports from iOS 17.5 that reference UIKit with different UUIDs. This is because of Rapid Security Updates.
 - MetricKit reports come from *all* devices in the field, not just devices where the user has enabled the privacy setting to share diagnostic data with app developers. The onus is on the app developer to share that they collect this data - it's not sent to Apple.
 - As of iOS 18 / macOS Sequoia, macOS Catalyst apps get diagnostic reports but not metric reports

## Remaining Questions

There are various things I'd still love to know:

 - What are the complete rules about where to find symbol files for system frameworks?
 - I've seen at least one report that has call stack frames from the same binary with different UUIDs. Specifically SwiftUI. What's going on there?
 
