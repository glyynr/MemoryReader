/**
* Date: October 7, 2013
* Authors: Talha Zekeriya Durmuş, talhazekeriyadurmus@gmail.com
* License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).
* Copyright: Rhodeus 2013
*/
module rhodeus.windows.dbghelp;
import rhodeus.windows.d;
import std.stdio;

enum IMAGE_DIRECTORY_ENTRY_EXPORT          =0;   // Export Directory
enum IMAGE_DIRECTORY_ENTRY_IMPORT          =1;   // Import Directory
enum IMAGE_DIRECTORY_ENTRY_RESOURCE        =2;   // Resource Directory
enum IMAGE_DIRECTORY_ENTRY_EXCEPTION       =3;   // Exception Directory
enum IMAGE_DIRECTORY_ENTRY_SECURITY        =4;   // Security Directory
enum IMAGE_DIRECTORY_ENTRY_BASERELOC       =5;   // Base Relocation Table
enum IMAGE_DIRECTORY_ENTRY_DEBUG           =6;   // Debug Directory
enum IMAGE_DIRECTORY_ENTRY_COPYRIGHT       =7;   // (X86 usage)
enum IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    =7;   // Architecture Specific Data
enum IMAGE_DIRECTORY_ENTRY_GLOBALPTR       =8;   // RVA of GP
enum IMAGE_DIRECTORY_ENTRY_TLS             =9;   // TLS Directory
enum IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    =10;   // Load Configuration Directory
enum IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   =11;   // Bound Import Directory in headers
enum IMAGE_DIRECTORY_ENTRY_IAT            =12;   // Import Address Table
enum IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   =13;   // Delay Load Import Descriptors
enum IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR =14;   // COM Runtime descriptor

extern(System){
	alias PVOID function( PVOID Base, BOOL MappedAsImage, USHORT DirectoryEntry, PULONG Size)  ImageDirectoryEntryToDataForm;
}
