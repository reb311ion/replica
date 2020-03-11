<h1 align="center"> REPLICA</h1>
<div align="center">
 <img src="logo.png" alt="Example" width="300" height="150"> 
  <p>
  <strong>
  TAME THE DRAGON
  </strong>
 </p>
</div>
<div align="center">
  <!-- Crates version -->
  <a >
    <img src="https://img.shields.io/badge/version-v1.0.0-green.svg"
  </a>
  <a >
    <img src="https://img.shields.io/badge/license-GPLv3-blue.svg"
  </a>
  <a >
    <img src="https://img.shields.io/badge/Features-13-red.svg"
  </a>
  </a>
</div>




## ✨Features

- ⚡ Disassemble missed instructions - Define code that Ghidra's auto analysis missed
- ⚡ Detect and fix missed functions - Define functions that Ghidra's auto analysis missed
- ⚡ Fix 'undefinedN' datatypes - Enhance Disassembly and Decompilation by fixing 
        'undefinedN' DataTypes 
- ⚡ Set MSDN API info as comments - Integrate information about functions, arguments
        and return values into Ghidra's disassembly listing in the form of comments
- ⚡ Tag Functions based on API calls - rename functions that calls one or more APIs with
        the API name and API type family if available
- ⚡ Detect and mark wrapper functions - Rename wrapper functions with the wrapping
        level and wrapped function name 
- ⚡ Fix undefined data and strings - Defines ASCII strings that Ghidra's auto analysis 
        missed and Converts undefined bytes in the data segment into DWORDs/QWORDs 
- ⚡ Detect and label crypto constants - Searche and label constants known to be associated
        with cryptographic algorithm in the code
- ⚡ Detect and comment stack strings - Find and post-comment stack strings 

- ⚡ Detect and label indirect string references - find and label references to existing strings

- ⚡ Detect and label indirect function calls - find and label references to existing functions

- ⚡ Rename Functions Based on string references - rename functions that references one
        or more strings with the function name followed by the string name.
- ⚡ Bookmark String Hints - Bookmark intersting strings (file extensions, browser agents, registry keys, etc..)

## 🚀 Installation:
Copy the repository files into any of `ghidra_scripts` directories and extract `db.7z`, directories can be found from `Window->Script Manager->Script Directories`

![image](https://user-images.githubusercontent.com/22657154/72688222-becde680-3b0d-11ea-8fb2-b9baa0239042.png)

Search for replica and enable `in tool` option
![image](https://user-images.githubusercontent.com/22657154/72688275-153b2500-3b0e-11ea-8fc2-77d6bfe9dc78.png)

Done!
![image](https://user-images.githubusercontent.com/22657154/72688313-6d722700-3b0e-11ea-95f6-2d27519ca9fd.png)

![image](https://user-images.githubusercontent.com/22657154/73777200-bcb48a80-4791-11ea-8f8c-7dec1aadc5d7.png)



## 🔒 License

Licensed under [GNU General Public License v3.0](https://github.com/reb311ion/replica/blob/master/LICENSE)

## ⛏️ BUG? OPEN NEW ISSUE   
OPEN [NEW ISSUE](https://github.com/reb311ion/replica/issues) 