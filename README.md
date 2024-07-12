<div align="center">
  <img src="assets/iat-tracer.ico">
</div>

--------------------------------------------------------------------------------

IAT-Tracer V2 is a plugin for [Tiny-Tracer](https://github.com/hasherezade/tiny_tracer) framework (by @hasherezade) for automatically detecting and resolving functions' parameters out of the IAT or trace logs (.tag files) of PE files.
The plugin has a GUI that allows the user to choose what imported or called functions to trace and watch and then automatically fills the parameters (library, function's name, and the number of parameters) into the "params.txt" file used by Tiny-Tracer.
Using this tool, the user can log all the dynamically called API functions and their arguments for each call.

# Changelog (V2)

- [X] .tag file parsing capabilities
- [X] Search box for automatic filtering by functions' names
- [X] Using .pickle file to reduce DB size
- [X] Pyinstaller compatibility for one file application (see Releases for downloading the .exe file)
- [X] Bug fixes

# Usage (IAT Tracing)

Example: tracing and watching interesting API functions from the [Vipasana](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Ransomware.Vipasana) ransomware binary.
<div align="center">
  <img src="assets/iat-tracer-v1.gif">
</div>

# Usage (.tag File Tracing)

Example: tracing and watching all the dynamically called functions from the [SameCoin](https://www.virustotal.com/gui/file/cff976d15ba6c14c501150c63b69e6c06971c07f8fa048a9974ecf68ab88a5b6) Wiper binary.

YouTube video:

[![.tag File Tracing](https://img.youtube.com/vi/tDYH0O-TAJw/0.jpg)](https://www.youtube.com/watch?v=tDYH0O-TAJw&ab_channel=Joavful)


Potential uses: malware analysis, reverse engineering, and debugging.
# Motivation

Currently, to trace and watch a program with the Tiny-Tracer framework one needs to perform several steps manually:
1. Finding which interesting functions are imported/called by the program.
2. Finding the library and the number of parameters required by those functions (this step usually requires online access to MSDN).
3. Manually writing each function's library, name, and number of parameters to the params.txt file.

The plugin is intended to automate this process, enabling the user to complete steps 1-3 offline in a matter of seconds.

# Installation

The plugin is intended to be used after the [installation of Tiny-Tracer](https://github.com/hasherezade/tiny_tracer/wiki/Installation).
```bat
git clone https://github.com/YoavLevi/IAT-Tracer.git
cd IAT-Tracer\
pip install -r requirements.txt
python .\IAT-Tracer.py
```

A more straightforward way to run the application is using the one-file executable: 
![image](https://github.com/user-attachments/assets/d3842904-e6c1-4c60-ab84-0ef1dd9697e3)

## Compatibility

Python 3

# How It Works

The plugin parses the PE header and then resolves each function (upon selection) and its parameters to the [params.txt](https://github.com/hasherezade/tiny_tracer/blob/master/install32_64/params.txt) file required by Tiny-Tracer.  
The plugin contains an offline dictionary ([apidb.pickle](https://github.com/YoavLevi/IAT-Tracer/blob/main/assets/apidb.pickle)) of all documented Windows API functions the author was able to reach.
The plugin was tested successfully against many executables. Upon a PE file with imports or called functions that are not part of the Windows API headers, the plugin would alert the user that some functions couldn't be resolved.  
The offline database was created automatically using a different Python script (not included in this directory but can be published upon request), a scrapper of Windows API headers files. Hence, there could be some bugs or inconsistencies. Whenever you encounter a bug, please report it to the issues tab of this repository.  
The GUI is built using [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) Python UI-library.  

# To-Do

- [ ] Fix inconsistency of the output file whenever both imported functions and visited functions are checked.

# Issues

Use [GitHub Issues](https://github.com/YoavLevi/IAT-Tracer/issues) for posting bugs and feature requests.
