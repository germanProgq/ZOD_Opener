# ZOD Opener

A small Windows command line tool in C++ that recursively extracts nested zip archives. If an extracted file is itself a zip, it opens that too, down to any depth. Encrypted archives are supported with a password.

It uses libzip for reading and extracting archives.

## Requirements

- Windows
- A C++ compiler and the Visual Studio solution in this repo (`Zip.sln`)
- libzip, installed through the included `packages.config` (NuGet)

## Build

Open `Zip.sln` in Visual Studio and build the `Zip` project. The dependencies restore from NuGet.

## Usage

Set the archive path and optional password in `Zip/Zip.cpp`, then run the built executable. The tool walks the archive, extracts each entry, and recurses into any nested `.zip` files it finds.

```text
Extracting file: ...
Extracting nested zip: ...
```

## Notes

This is a personal utility for unpacking deeply nested archives. Use it on files you trust, since extracting unknown archives can write a large number of files to disk.
