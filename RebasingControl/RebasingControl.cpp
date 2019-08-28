#include <iostream>
#include <fstream>
#include <Windows.h>
#include <vector>
#include <map>
#include<iomanip>

using namespace std;

#define COMP_PARAM(STR, TARGET)  _strnicmp(STR, TARGET, strlen(TARGET)) == 0
#define GET_STR_PARAM(STR ,SOURCE, TARGET)      if(COMP_PARAM(SOURCE, TARGET)) STR = string(SOURCE).substr(strlen(TARGET));
#define GET_BOOL_PARAM(OUT, SOURCE, TARGET)     if(COMP_PARAM(SOURCE, TARGET)) OUT = true;

bool CHECK_PARAM(const char* STR, std::initializer_list<const char*> LIST){
    int result = 0;                                 
    for(auto item : LIST) {                        
        if(_strnicmp(STR, item, strlen(item)) == 0 and strlen(item) == strlen(STR)){   
            result ++;                              
        }                                           
    }                                               
    return result == 1;
}

#define WARNING_MSG(x) cout << "[WARNING] : " << __func__ << "@" << __LINE__ << " : " << x << endl;
#define FAILED_MSG(x)  cout << "[FAILED]  : " << __func__ << "@" << __LINE__ << " : " << x << endl;
#define DEBUG_MSG(x)   cout << "[DEBUG]   : " << __func__ << "@" << __LINE__ << " : " << x << endl;
#define ERR_EXIT       {char Buffer[256];strerror_s(Buffer, 256, errno);FAILED_MSG(Buffer);exit(1);}

char* content = nullptr;

PIMAGE_DOS_HEADER p_dos_header;
PIMAGE_FILE_HEADER p_file_header;
// OPTIONAL_HEADER
uint32_t* pD_RelocRVA = nullptr;     // pointer Directories Relocation file offset
uint32_t* pD_RelocSize = nullptr;
uint32_t* pD_ImportRVA = nullptr;
uint32_t* pD_ImportSize = nullptr;
// END ATTENTION
PIMAGE_SECTION_HEADER reloc_section = nullptr;

size_t pFile_Sections;          // offset to sections (pFile)
size_t attri_SectionAligment;
size_t attri_FileAlignment;
size_t attri_ImageBase;

std::vector<uint32_t> relocation_table;

//                                          pointer to Import Address Table item  
std::map<PIMAGE_IMPORT_DESCRIPTOR, std::map<uint32_t *, PIMAGE_IMPORT_BY_NAME>> import_table;



uint32_t get_pFile_from_RVA(uint32_t RVA) {
    uint32_t pFile = pFile_Sections;
    PIMAGE_SECTION_HEADER section = nullptr;
    for (int i = 0; i < p_file_header->NumberOfSections; ++i) {
        section = (PIMAGE_SECTION_HEADER)(content + pFile);
        if (section->VirtualAddress <= RVA and section->VirtualAddress + section->Misc.VirtualSize > RVA) {
            return section->PointerToRawData + RVA - section->VirtualAddress;
        }
        pFile += sizeof(IMAGE_SECTION_HEADER);
    }
    return 0;
}

uint32_t get_RVA_from_pFile(uint32_t a_pFile) {
    uint32_t pFile = pFile_Sections;
    PIMAGE_SECTION_HEADER section = nullptr;
    for (int i = 0; i < p_file_header->NumberOfSections; ++i) {
        section = (PIMAGE_SECTION_HEADER)(content + pFile);
        if (section->PointerToRawData <= a_pFile and section->PointerToRawData + section->SizeOfRawData > a_pFile) {
            return section->VirtualAddress + a_pFile - section->PointerToRawData;
        }
        pFile += sizeof(IMAGE_SECTION_HEADER);
    }
    return 0;
}

string get_section_from_RVA(uint32_t RVA) {
    uint32_t pFile = pFile_Sections;
    PIMAGE_SECTION_HEADER section = nullptr;
    for (int i = 0; i < p_file_header->NumberOfSections; ++i) {
        section = (PIMAGE_SECTION_HEADER)(content + pFile);
        if (section->VirtualAddress <= RVA and section->VirtualAddress + section->Misc.VirtualSize > RVA) {
            return string((char*)&(section->Name));
        }
        pFile += sizeof(IMAGE_SECTION_HEADER);
    }
    return "";
}

void print_reloation_record_header() {
    cout << "   pFile\t  Section\t   RVA\t\t   VA\t\t  Value" << endl;
    cout << "---------------------------------------------------------------------------" << endl;
}

void print_relocation_record_via_RVA(uint32_t i) {
    uint32_t file_offset = get_pFile_from_RVA(i);
    string section = get_section_from_RVA(i);
    uint32_t* value = (uint32_t*)(content + file_offset);
    if (file_offset == 0) {
        cout << setfill('?') << setw(8) << "?";
    }
    else {
        cout << " 0x" << setfill('0') << setw(8) << hex << file_offset;
    }
    cout << "\t" << setw(8) << setfill(' ') << section;
    cout << "\t0x" << setfill('0') << setw(8) << hex << i;
    cout << "\t0x" << setfill('0') << setw(8) << hex << i + attri_ImageBase;
    if (file_offset == 0) {
        cout << setfill('?') << setw(8) << "?";
    }
    else {
        cout << "\t0x" << setfill('0') << setw(8) << hex << *value << endl;
    }
    
}

void print_import_table_header(PIMAGE_IMPORT_DESCRIPTOR i) {
    cout << endl;
    cout << "  " << (content + get_pFile_from_RVA(i->Name)) << endl;
    cout << "-----------------------------------------------------------------------------" << endl;
    cout << "\t  pFile \t   RVA \t\t Hint \t\t Name" << endl;
    cout << "-----------------------------------------------------------------------------" << endl;
}

void printf_import_table_header(PIMAGE_IMPORT_DESCRIPTOR pModule, std::vector<PIMAGE_IMPORT_BY_NAME> vList) {
    cout << "  Module  " << (content + get_pFile_from_RVA(pModule->Name)) << endl;
}

void print_import_table_item(pair<uint32_t*, PIMAGE_IMPORT_BY_NAME> j) {
    uint32_t pFile = (uint32_t)((uint8_t*)j.first - (uint8_t*)content);
    cout << "\t0x" << setfill('0') << setw(8) << hex << pFile;
    cout << "\t0x" << setfill('0') << setw(8) << hex << get_RVA_from_pFile(pFile);
    cout << "\t0x" << setfill('0') << setw(4) << hex << j.second->Hint;
    cout << "\t\t" << (char*)& j.second->Name;
    cout << endl;
}

void print_usage() {
}

int main(int argc, char* argv[]){
    cout << endl;
    if (argc < 3) { print_usage(); exit(0); }
    string a_file(argv[1]);
    string a_action;
    string a_basing = "RVA";
    string a_table = "reloc";
    uint32_t a_offset = 0;

    string a_str_offset;
    bool a_remove_all = false;
    if (a_file.empty() or a_file.at(0) == '-') {
        FAILED_MSG("Please specify a PE file!");
        exit(0);
    }
    for (int i = 2; i < argc; ++i) {
        GET_STR_PARAM(a_action, argv[i], "--action=");
        GET_STR_PARAM(a_table, argv[i], "--table=");
        GET_STR_PARAM(a_basing, argv[i], "--basing=");
        GET_STR_PARAM(a_str_offset, argv[i], "--offset=");
    }
    if (!CHECK_PARAM(a_action.c_str(), { "list", "add", "remove","remove-all" })) {
        if (!a_action.empty()) 
            FAILED_MSG("Unknow action : " << a_action << endl);
        print_usage();
        exit(0);
    }
    if (!CHECK_PARAM(a_basing.c_str(), { "ImageBase+RVA", "RVA+ImageBase","RVA", "pFile" })) {
        if (!a_basing.empty())
            FAILED_MSG("Unknow basing index : " << a_basing << endl);
        print_usage();
        exit(0);
    }
    if (!CHECK_PARAM(a_table.c_str(), { "reloc","relocation", "import", "all" })) {
        if(!a_table.empty())
            FAILED_MSG("Unknow table : " << a_table << endl);
        print_usage();
        exit(0);
    }
    if (a_table.at(0) == 'r' or a_table.at(0) == 'R')
        a_table = "reloc";
    sscanf_s(a_str_offset.c_str(), "%x", &a_offset);
    if (a_action != "list" and (a_str_offset.empty() or a_offset == 0)) {
        FAILED_MSG("Please specify offset!");
        print_usage();
        exit(0);
    }

    fstream file;
    size_t pFile = 0;
    file.open(a_file, ios::in | ios::binary);
    if (!file) ERR_EXIT;
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);

    content = (char*)malloc(file_size);
    if (content == nullptr) ERR_EXIT;
    file.read(content, file_size);
    file.close();

    if (file_size < 0x400) {
        FAILED_MSG(a_file << " maybe not a ordinary PE file");
        exit(0);
    }
    p_dos_header = (PIMAGE_DOS_HEADER)(content);
    
    if (p_dos_header->e_magic != 0x5a4d) {
        FAILED_MSG( a_file << " is not a valid DOS file!");
        exit(0);
    }

    uint32_t PE_MAGIC;
    memcpy((void*)& PE_MAGIC, content + p_dos_header->e_lfanew, sizeof(uint32_t));
    if (PE_MAGIC != 0x00004550) {   // 'PE\0\0'
        FAILED_MSG(a_file << " is not a valid PE file!");
        exit(0);
    }
    pFile += p_dos_header->e_lfanew + sizeof(uint32_t);
    p_file_header = (PIMAGE_FILE_HEADER)(content + pFile);
    pFile += sizeof(IMAGE_FILE_HEADER);

    if (p_file_header->NumberOfSections < 1) {
        FAILED_MSG("Section count is " << p_file_header->NumberOfSections << " but it shouldn't less than 1");
        exit(0);
    }


    if (p_file_header->Machine == 0x14c) {
        PIMAGE_OPTIONAL_HEADER32 p_header;
        p_header = (PIMAGE_OPTIONAL_HEADER32)(content + pFile);
        if (p_header->NumberOfRvaAndSizes != 0x10) {
            FAILED_MSG(a_file << " is not a ordinary PE file!  -->  Number of Data Direcotries is " << hex << p_header->NumberOfRvaAndSizes << " But it should be 0x10");
            exit(0);
        }
        attri_SectionAligment = p_header->SectionAlignment;
        attri_FileAlignment = p_header->FileAlignment;
        attri_ImageBase = p_header->ImageBase;
        pFile += sizeof(IMAGE_OPTIONAL_HEADER32);
        pD_RelocRVA = (uint32_t*)(content + pFile - 11 * sizeof(IMAGE_DATA_DIRECTORY));
        pD_RelocSize = (uint32_t*)(content + pFile - 11 * sizeof(IMAGE_DATA_DIRECTORY) + sizeof(uint32_t));
        pD_ImportRVA = (uint32_t*)(content + pFile - 15 * sizeof(IMAGE_DATA_DIRECTORY));
        pD_ImportSize = (uint32_t*)(content + pFile - 15 * sizeof(IMAGE_DATA_DIRECTORY) + sizeof(uint32_t));
    }
    else if (p_file_header->Machine == 0x8664) {
        PIMAGE_OPTIONAL_HEADER64 p_header;
        p_header = (PIMAGE_OPTIONAL_HEADER64)(content + pFile);
        if (p_header->NumberOfRvaAndSizes != 0x10) {
            FAILED_MSG(a_file << " is not a ordinary PE file!  -->  Number of Data Direcotries is " << hex << p_header->NumberOfRvaAndSizes << " But it should be 0x10");
            exit(0);
        }
        attri_SectionAligment = p_header->SectionAlignment;
        attri_FileAlignment = p_header->FileAlignment;
        attri_ImageBase = p_header->ImageBase;
        pFile += sizeof(IMAGE_OPTIONAL_HEADER32);
        pD_RelocRVA = (uint32_t*)(content + pFile - 11 * sizeof(IMAGE_DATA_DIRECTORY));
        pD_RelocSize = (uint32_t*)(content + pFile - 11 * sizeof(IMAGE_DATA_DIRECTORY) + sizeof(uint32_t));
        pD_ImportRVA  = (uint32_t*)(content + pFile - 15 * sizeof(IMAGE_DATA_DIRECTORY)); 
        pD_ImportSize = (uint32_t*)(content + pFile - 15 * sizeof(IMAGE_DATA_DIRECTORY) + sizeof(uint32_t));
    }
    else {
        FAILED_MSG("Unsupported Machine Code --> " << p_file_header->Machine);
        exit(0);
    }

    pFile_Sections = pFile;
    for (size_t i = 0; i < p_file_header->NumberOfSections; ++i) {
        reloc_section = (PIMAGE_SECTION_HEADER)(content + pFile);
        if (_strnicmp((const char*)&reloc_section->Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            break;
        }
        pFile += sizeof(IMAGE_SECTION_HEADER);
    }
    if (_strnicmp((const char*)reloc_section->Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME) != 0) {
        FAILED_MSG("Relocation Section not found!");
        exit(0);
    }

    pFile = reloc_section->PointerToRawData;
 
    

    for (size_t offset = 0; offset < *pD_RelocSize; ) {
        uint32_t RVA_of_block;
        uint32_t size_of_block;
        memcpy((void*)& RVA_of_block, content + pFile + offset, sizeof(uint32_t));
        memcpy((void*)& size_of_block, content + pFile + offset + sizeof(uint32_t), sizeof(uint32_t));
        for (size_t i = 2 * sizeof(uint32_t); i < size_of_block; i += sizeof(uint16_t)) {
            uint16_t item;
            memcpy((void*)& item, content + pFile + offset + i, sizeof(uint16_t));
            uint16_t type = item & 1111000000000000;
            if (type == 0)   continue;  // skip empty record
            relocation_table.push_back(RVA_of_block + (item & uint16_t(4095)));
        }
        offset += size_of_block;
    }

    uint32_t pImportFile = get_pFile_from_RVA(*pD_ImportRVA);
    if (pImportFile == 0) {
        FAILED_MSG("No import table");
        exit(0);
    }
    while (*(content+pImportFile) != 0) {     // get Import Directory Table
        PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)(content + pImportFile);
        map<uint32_t *,PIMAGE_IMPORT_BY_NAME> pName = {};
        for (uint32_t* pImportAddressTable = (uint32_t*)(content + get_pFile_from_RVA(pDesc->FirstThunk)); *(pImportAddressTable) != 0; ++pImportAddressTable)
            pName[pImportAddressTable] = (PIMAGE_IMPORT_BY_NAME)(content + get_pFile_from_RVA(*pImportAddressTable));
        import_table[pDesc] = pName;
        pImportFile += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }


    uint32_t target_RVA = 0;
    uint32_t target_pFile = 0;
    if (_stricmp(a_basing.c_str(), "ImageBase+RVA") == 0 || _stricmp(a_basing.c_str(), "RVA+ImageBase") == 0) {
        target_RVA =  a_offset - attri_ImageBase;
    }
    else if (_stricmp(a_basing.c_str(), "pFile") == 0) {
        target_RVA = get_RVA_from_pFile(a_offset);
    }
    else if(_stricmp(a_basing.c_str(), "RVA") == 0){
        target_RVA = a_offset;
    }
    target_pFile = get_pFile_from_RVA(target_RVA);
    if (_stricmp(a_action.c_str(), "list") == 0) {
        if (a_offset != 0) {  // list single
            if (_stricmp(a_table.c_str(), "reloc") == 0 or _stricmp(a_table.c_str(), "all") == 0) {
                for (auto& i : relocation_table) {
                    if (i == target_RVA) {
                        print_reloation_record_header();
                        print_relocation_record_via_RVA(i);
                    }
                }
            }
            if (_stricmp(a_table.c_str(), "import") == 0 or _stricmp(a_table.c_str(), "all") == 0) {
                for (auto& i : import_table) {
                    for (auto& j : i.second) {
                        if ((uint32_t)((uint8_t*)j.first - (uint8_t*)content) == target_pFile) {
                            print_import_table_header(i.first);
                            print_import_table_item(j);
                        }
                    }
                }
            }
        }
        else {
            if (_stricmp(a_table.c_str(), "reloc") == 0 or _stricmp(a_table.c_str(), "all") == 0) {
                print_reloation_record_header();
                for (auto i : relocation_table)
                    print_relocation_record_via_RVA(i);
                cout << endl;
            }
            if (_stricmp(a_table.c_str(), "import") == 0 or _stricmp(a_table.c_str(), "all") == 0) {
                for (auto& i : import_table) {
                    print_import_table_header(i.first);
                    for (auto& j : i.second)
                        print_import_table_item(j);
                }
            }
        }
    }
    else if (_stricmp(a_action.c_str(), "remove-all") == 0) {

    }
    else if (_stricmp(a_action.c_str(), "add") == 0) {

    }
    else if (_stricmp(a_action.c_str(), "remove") == 0) {

    }
NORMAL_EXIT:
    cout << endl;
    free(content);
}