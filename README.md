# su_ruby_decryptor
A tiny CLI that decrypts Sketchup's RBE/RBS file format into plain Ruby. This only supports RBS version 2.0, so older encrypted files are not supported (for now).

## How to build
* You must have at least `Visual Studio 2017` installed (haven't tested it on anything else)
* Make sure the `Desktop development with C++` workload is enabled using `Visual Studio Installer`
  * Make sure `Visual C++ tools for CMake` is enabled
* Open `Visual Studio x64 Native Tools Command Prompt`
* Navigate to the root source code directory
* `cmake .`
* `cmake --build .`
* `su_ruby_decryptor.exe` will be in the `Debug` sub-directory
* Open cmd or powershell and use the command `.\su_ruby_decryptor.exe "path-to-rbe-or-rbs-file"`
  * Add ` > output_file_name.rb` to this command to write the output to a file
