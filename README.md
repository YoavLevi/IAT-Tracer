<div align="center">
  <img src="assets/iat-tracer.ico">
</div>

--------------------------------------------------------------------------------

IAT-Tracer is a plugin for [Tiny-Tracer](https://github.com/hasherezade/tiny_tracer) framework (by @hasherezade) that automatically detect and resolve functions' parameters out of the IAT of a PE file and an offline database.
The plugin has a GUI that allows the user to choose what imported functions to trace and then automatically fills the parameters (library, function's name and number of parameters) into the "params.txt" used by Tiny-Tracer.

# Usage

<div align="center">
  <img src="assets/iat-tracer.gif">
</div>

# Installation

```bat
git clone https://github.com/YoavLevi/IAT-Tracer.git
cd IAT-Tracer\
pip install -r requirements.txt
python .\IAT-Tracer.py
```
# How It Works

The GUI is built using [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) python UI-library.  
The plugin first parses the PE header using the "pefile" python module and then resolves each import (upon selection) and its parameters to the ["params.txt"](https://github.com/hasherezade/tiny_tracer/blob/master/install32_64/params.txt) file required by Tiny-Tracer.  
The plugin contains an offline dictionary ([apidb.json](https://github.com/YoavLevi/IAT-Tracer/blob/main/assets/apidb.json) of all documented Windows API functions.  
The plugin was tested successfully against many executables. Upon a PE file with imports which are not part of the Windows API headers, the plugin would alert the user that some functions couldn't be resolved.  
The offline database was created automatically using a different python script (which is not included in this directory but can be published upon requests) which is a scrapper of Windows API headers files. Hence, there may be some bugs or inconsistencies. Once encountered an bug, you are kindly requested to report it to the issues tab of this repository.  

# To-Do

- [ ] incomplete task
- [ ] Add a search-box for manually tracing API functions that are resolved dynamically (e.g., via LoadLibrary and GetProcAddress).

# Issues
Use [GitHub Issues](https://github.com/YoavLevi/IAT-Tracer/issues) for posting bugs and feature requests.
