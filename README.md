# ZOD recursive unzipper

This repository contains a tool for recursively unzipping massive zip files and overriding Windows Defender to prevent interference with the process.

## Features

- **Recursive Unzipping**: The tool is capable of recursively unzipping zip files within zip files to an arbitrary depth.
- **Windows Defender Override**: It includes functionality to override Windows Defender, ensuring uninterrupted operation during the unzipping process.
- **Customizable Configuration**: Users can configure various aspects of the unzipping process, such as the target directory and password for encrypted zip files.

## Requirements

- **Operating System**: Windows (tested on Windows 10)
- **C++ Compiler**: Compatible C++ compiler for building the source code.
- **Windows Defender Configuration**: Admin privileges may be required to modify Windows Defender settings.

## Usage

1. **Clone the Repository**: Clone this repository to your local machine using the following command:

   ```bash
   git clone https://github.com/your-username/mass-unzipper.git
   ```

2. **Build the Tool**: Navigate to the cloned directory and build the tool using your preferred C++ compiler.

3. **Configure Windows Defender Override**: Follow the instructions provided in the `windows_defender_override.md` file to configure Windows Defender to allow the tool to run without interference.

4. **Run the Tool**: Execute the compiled binary and provide the necessary arguments to specify the target zip file, destination directory, and any other options.

   ```bash
   mass_unzipper.exe -zip "path/to/your/zipfile.zip" -dest "path/to/destination/directory" -password "your_zip_password"
   ```

5. **Sit Back and Relax**: The tool will recursively unzip the specified zip file and all nested zip files while bypassing Windows Defender detection.

## Contribution

Contributions are welcome! If you encounter any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## Disclaimer

**Use this tool responsibly and only on files that you have permission to access.** The authors of this tool are not responsible for any misuse or unauthorized access to files.

---

Feel free to customize this template according to your specific requirements and project details. If you have any questions or need further assistance, don't hesitate to ask!