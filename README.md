# MXSymbolicate

`MXSymbolicate.py` is an example python script for symbolicating call stacks in json-formatted diagnostic reports produced by [MetricKit](https://developer.apple.com/documentation/metrickit).

It's specifically written to deal with the diagnostic reports as saved by the [Olive Tree Bible App](https://apps.apple.com/us/app/bible-app-read-study-daily/id332615624), in which iOS report json is embedded in a root object with some other properties for convenience. The script will not work if given an unmodified MetricKit diagnosic report, but can be modified reasonably easily to do so. It's meant as an example, not as a plug-and-play tool.

Olive Tree's reports look something like this:

```
{
    "app_version": "7.15.1.1958",
    "device_model": "iPhone12,1",
    "os_version": "17.1.1",
    "timestamp": "2023-11-22T08:59:34.783Z",
    "payload": {
        ...MetricKit payload here...
    }
}
```

They get saved to disk on the device and included when sending diagnostics to our support department.

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

When called in any of these ways, the script will print some metadata from the report and the symbolicated call stacks.

## Symbolicating frames in system libraries

`MXSymbolicate` uses the dSYM provided to it via `--symbols-path` to symbolicate call stack frames in the source app. But it needs separate dSYM files for system libraries like `UIKit` and `libsystem_kernel.dylib`. As it turns out, these are available for any iOS version that's been on a device you've connected to Xcode in `~/Library/Developer/Xcode/iOS DeviceSupport`. Folders there appear to be named according to device and OS version: `<device type> <os version> <os build number>`, ex. `iPad13,16 17.0 (21A329)`.

Via trial and error, I've figured out that:

 - Binaries with names like `libsystem_kernel.dylib` and `libsystem_pthread.dylib` (beginning with `lib` and ending with `.dylib`) are in `iOS DeviceSupport/<device>/Symbols/usr/lib/system/<name>`
 - Other names like `UIKitCore` and `Foundation` are either in `iOS DeviceSupport/<device>/Symbols/System/Library/` or `.../Symbols/System/PrivateFrameworks`.

The script finds a device folder there that matches the iOS version specified in the report, and then follows those rules to find symbol files for system frameworks it finds in call stack frames.

I imagine there are some frameworks that don't follow those rules, or situations in which those rules don't work - I'll figure that out if and when I run into them in a crash report.

## Useful Resources

There's a surprising lack of documentation on how exactly to use the information in the diagnostic reports. But here's what I used to figure out how to get this far:

 - Introduction of MetricKit at WWDC 2019: [Improving Battery Life and Performance](https://developer.apple.com/videos/play/wwdc2019/417/)
 - WWDC 2020: [What's New in MetricKit](https://developer.apple.com/videos/play/wwdc2020/10081/)
 - [Apple documentation on symbolicating](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report)
 - [Apple Developer Forum thread](https://developer.apple.com/forums/thread/681967) on how to plug the values in the call stack tree into `atos`
 - [Where to find system framework dSYM files](https://www.finik.net/2017/03/20/iOS-Crash-Symbolication-for-dummies-Part-2/)

## Remaining Questions

There are various things I'd still love to know:

 - In a crash diagnostic, how do I know which thread actually crashed?
 - What does the `callStackPerThread` property in the call stack mean?
 - What's the purpose of the `address` field in the call stack frame objects?
 - What situations trigger disk write exceptions and CPU exceptions?
 - What are the complete rules about where to find dSYM files for system frameworks?
 - Call stacks are formatted as recursive objects, with each frame having a `subFrames` object. Usually these contain only one object, but sometimes there's more. Why?
 - Sometimes the `callStackRootFrames` array has more than one object in it. Why?