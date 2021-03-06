# Driver Security Analyzer

This repository contains the source code of iDEA (an alias for Apple Driver Security Analyzer), our static analysis tool for analyzing the security of Apple kernel drivers.

## Compatibility 

iDEA works on IDA pro 7.0. It is able to analyze x86_64 (macOS) and arm64 (iOS/iPadOS/tvOS) binaries. It's analysis on arm64e binaires, i.e, binaries with PAC tags (e.g., watchOS), is not complete yet.

## Description of directories

* **arm64**: Analyzer for drivers on arm64 platforms, including iOS/iPadOS/tvOS. Arm64Analyzer contains the main body of the analyzer, other files are the individual stages used by Arm64Analyzer.
* **x86_64**: Analyzer for drivers on x86_64 platforms, i.e., macOS. X64Analyzer contains the main body of the analyzer.
* **utils**: Utilities used by arm64 and x86_64 analyzers
* **batch**: Commands for loading driver binaires into IDA pro and analyze them in batch, mainly usefull for macOS drivers since arm64 drivers are bundled into a single kernelcache
* **ida_kernelcache**: The source code of Brandon Azad's tool ida_kernelcache. iDEA uses some functionalities from ida_kernelcache, for untagging pointers and forcing IDA pro to recognize functions. 
* **results**: Directory to store iDEA's analysis results
* **Headers**: C header files generated from the kernel binary, which contains kernel data structures and will be imported during the preprocessing of analyzers.
* **data**: JSON files generated by parsing the kernel headers and iOS/iPadOS kernelcache, which is important for analyzing unnamed merged kernelcache like tvOS. These JSON files can be generated by using functions in the utils direcotry.
* **xnusrc**: Directory to place xnu source code. This is used by HeaderClangParser in utils to import kernel function types from xnu source.


## Requirements

Some functionalities in iDEA use Capstone disassembler and Triton symbolic execution engine. Please install [Capstone](https://github.com/aquynh/capstone) and [Triton](https://github.com/JonathanSalwan/Triton) before using iDEA. Some results of iDEA will be stored in mongodb, please also install mongodb and pymongo first.
 
