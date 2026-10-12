#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint16_t read16(uint8_t* buffer, uint32_t offset) {
	return ((uint16_t)buffer[offset + 1] << 8) | (uint16_t)buffer[offset];
}

uint32_t read32(uint8_t* buffer, uint32_t offset) {
	return 	((uint32_t)buffer[offset + 3] << 24) | ((uint32_t)buffer[offset + 2] << 16) | ((uint32_t)buffer[offset + 1] << 8) | (uint32_t)buffer[offset];
}


uint32_t rvaToOffset(uint32_t rva, uint8_t* buffer, uint32_t sectionStart, uint16_t numSections) {

	for (int i = 0; i < numSections; i++) {
		uint32_t sectionOffset = sectionStart + i * 40;
		uint32_t virtulaSize = read32(buffer, sectionOffset + 8);
		uint32_t virtuladdr = read32(buffer, sectionOffset + 12);
		uint32_t pointerToRawData = read32(buffer, sectionOffset + 20);

		if (rva >= virtuladdr && rva < virtulaSize + virtuladdr) {
			uint32_t rvaResult = pointerToRawData + (rva - virtuladdr);
			return rvaResult;
		}
		
	}
	return 0;
}

int main(int argc, char **argv) {

	//ensure a file path was provided
	if (argc < 2) {
		printf("You have to insert a path");
			return 1;
	}

	char* path = argv[1];
	
	FILE *fp;

	//open file and read binary.
	fp = fopen(path, "rb");
	if (fp == NULL) {
		printf("The file is NULL");
		return 1;
	}

	//measure file size by seeking to the end

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	fseek(fp, 0, SEEK_SET);


	if (size < 2) {
		printf("Out of limit");
		fclose(fp);
		return 1;
	}

	//Memory Allocation.
	uint8_t *data = malloc(size);
	if (data == NULL) {
		printf("malloc");
		return 1;
	}

	//Read the file.
	size_t bytesRead = fread(data, 1, size, fp);
	if (bytesRead != size) {
		printf("something changed");
		fclose(fp);
		free(data);
		return 1;
	}

	if (data[0] != 'M' || data[1] != 'Z') {
		printf("not a valid PE file: missing MZ signature");
		fclose(fp);
		free(data);
		return 1;
	}

	//borders check

	if (size < 0x40) {
		printf("Out of borders");
		fclose(fp);
		free(data);
		return 1;
	}

	uint32_t e_lfanew = read32(data, 0x3C);
	
	if (e_lfanew + 4 > size) {
		printf("e_lfanew points outside file");
		fclose(fp);
		free(data);
		return 1;
	}

	if (data[e_lfanew + 0] != 'P' || data[e_lfanew + 1] != 'E' || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) {
		printf("not a valid PE file: missing PE signature");
		fclose(fp);
		free(data);
		return 1;
	}

	if (e_lfanew + 4 + 20 > size) {
		printf("file too small for PE File Header");
		fclose(fp);
		free(data);
		return 1;
	}

	
	uint16_t machine = read16(data, e_lfanew + 4);

	switch (machine) {
	case 0x8664:
		printf("x64 architecture\n");
		break;
	case 0x14C:
		printf("x86 architecture\n");
		break;
	default:
		printf("unknown architecture\n");
		break;
	}

	uint16_t numSections = read16(data, e_lfanew + 6);
	uint16_t sizeOfOptionalHeader = read16(data, e_lfanew + 20);
	uint16_t characteristics = read16(data, e_lfanew + 22);

	if (characteristics & 0X2000) {
		printf("Its dll file \n");
	}
	else printf("Its executable file \n");
	

	// Section Headers

	uint32_t sectionStart = e_lfanew + 24 + sizeOfOptionalHeader;
	

	if (sectionStart + numSections * 40 > size) {
		printf("too big");
		fclose(fp);
		free(data);
		return 1;
	}

	for (int i = 0; i < numSections; i++) {
		uint32_t sectionOffset = sectionStart + i * 40;
		printf("Name: %.8s\n", &data[sectionOffset]);

		uint32_t virtulaSize = read32(data, sectionOffset + 8);
		uint32_t virtuladdr = read32(data, sectionOffset + 12);
		uint32_t sizeOfRawData = read32(data, sectionOffset + 16);
		uint32_t pointerToRawData = read32(data, sectionOffset + 20);

		printf("Virtual Size = %X\n", virtulaSize);
		printf("Virtual Addr. = %X\n", virtuladdr);
		printf("Raw Data Size = %X\n", sizeOfRawData);
		printf("Raw Addr. = %X\n", pointerToRawData);
	}

	uint32_t optionalHeaderStart =  e_lfanew + 24;
	uint16_t magic = read16(data, optionalHeaderStart);
	uint32_t dataDirStart = 0;

	switch (magic) {
	case 0x20B:
		dataDirStart = optionalHeaderStart + 112;
		break;
	case 0x10B:
		dataDirStart = optionalHeaderStart + 96;
		break;
	default:
		printf("not a valid PE file\n");
		fclose(fp);
		free(data);
		return 1;
	}

	uint32_t importRva = read32(data, dataDirStart + 8);
	uint32_t importOffset = rvaToOffset(importRva, data, sectionStart, numSections);

	int i = 0;
	while(1) {
		uint32_t locationOffset = importOffset + i * 20;

		if (locationOffset + 20 > size) {
			printf("too big");
			fclose(fp);
			free(data);
			return 1;
		}

		uint32_t nameRva = read32(data, locationOffset + 12);
		if (nameRva == 0) {
			break;
		}
		uint32_t nameOffset = rvaToOffset(nameRva, data, sectionStart, numSections);
		printf("DLL = %s\n", &data[nameOffset]);
		i++;


	}

	fclose(fp);

	free(data);

}

