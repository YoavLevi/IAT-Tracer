<div align="center">
  <img src="assets/iat-tracer.ico">
</div>

--------------------------------------------------------------------------------

IAT-Tracer is a plugin for [Tiny-Tracer](https://github.com/hasherezade/tiny_tracer) framework (by @hasherezade) for automatically detecting and resolving functions' parameters out of the IAT of PE files.
The plugin has a GUI that allows the user to choose what imported functions to trace and then automatically fills the parameters (library, function's name, and the number of parameters) into the "params.txt" file used by Tiny-Tracer.

# Usage

Example: tracing and watching interesting API functions from the [Vipasana](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Ransomware.Vipasana) ransomware binary.
<div align="center">
  <img src="assets/iat-tracer.gif">
</div>

Potential uses: malware analysis, reverse engineering, and debugging.
# Motivation

Currently, to trace and watch a program with the Tiny-Tracer framework one needs to perform several steps manually:
1. Find out which interesting functions are used by the program.
2. Find out the library and the number of parameters required by those functions (this step usually requires online access to MSDN).
3. Write each function's library, name, and number of parameters to the params.txt file.

The plugin is intended to automate this process, enabling the user to complete steps 1-3 offline in a matter of seconds.

# Installation

The plugin is intended to be used after the [installation of Tiny-Tracer](https://github.com/hasherezade/tiny_tracer/wiki/Installation).
```bat
git clone https://github.com/YoavLevi/IAT-Tracer.git
cd IAT-Tracer\
pip install -r requirements.txt
python .\IAT-Tracer.py
```
## Compatibility

Python 3

# How It Works

The plugin parses the PE header and then resolves each import (upon selection) and its parameters to the [params.txt](https://github.com/hasherezade/tiny_tracer/blob/master/install32_64/params.txt) file required by Tiny-Tracer.  
The plugin contains an offline dictionary ([apidb.json](https://github.com/YoavLevi/IAT-Tracer/blob/main/assets/apidb.json)) of all documented Windows API functions.  
The plugin was tested successfully against many executables. Upon a PE file with imports that are not part of the Windows API headers, the plugin would alert the user that some functions couldn't be resolved.  
The offline database was created automatically using a different Python script (which is not included in this directory but can be published upon requests) which is a scrapper of Windows API headers files. Hence, there could be some bugs or inconsistencies. Once encountered a bug, you are kindly requested to report it to the issues tab of this repository.  
The GUI is built using [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) Python UI-library.  

# To-Do

- [ ] Add a search box for manually watching API functions that are resolved dynamically (e.g., via LoadLibrary and GetProcAddress).

# Issues

Use [GitHub Issues](https://github.com/YoavLevi/IAT-Tracer/issues) for posting bugs and feature requests.
