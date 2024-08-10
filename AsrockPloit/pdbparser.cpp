#include "ntdll.h"
#include "pdbparser.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <urlmon.h>

#pragma pack(push, 1)
struct SuperBlock
{
	constexpr static char kMagic[] =
	{
		0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F,
		0x43, 0x2B, 0x2B, 0x20, 0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30,
		0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00
	};

	char          FileMagic[sizeof(kMagic)];
	std::uint32_t BlockSize;
	std::uint32_t FreeBlockMapBlock;
	std::uint32_t NumBlocks;
	std::uint32_t NumDirectoryBytes;
	std::uint32_t Unknown;
	std::uint32_t BlockMapAddr;

	bool is_magic_valid() const
	{
		return 0 == memcmp(FileMagic, kMagic, sizeof(kMagic));
	}
};

struct DBIHeader
{
	std::int32_t	VersionSignature;
	std::uint32_t	VersionHeader;
	std::uint32_t	Age;
	std::uint16_t	GlobalStreamIndex;
	std::uint16_t	BuildNumber;
	std::uint16_t	PublicStreamIndex;
	std::uint16_t	PdbDllVersion;
	std::uint16_t	SymRecordStream;
	std::uint16_t	PdbDllRbld;
	std::int32_t	ModInfoSize;
	std::int32_t	SectionContributionSize;
	std::int32_t	SectionMapSize;
	std::int32_t	SourceInfoSize;
	std::int32_t	TypeServerSize;
	std::uint32_t	MFCTypeServerIndex;
	std::int32_t	OptionalDbgHeaderSize;
	std::int32_t	ECSubstreamSize;
	std::uint16_t	Flags;
	std::uint16_t	Machine;
	std::uint32_t	Padding;
};
#pragma pack(pop)

struct PUBSYM32
{
	std::uint16_t reclen;     // Record length
	std::uint16_t rectyp;     // S_PUB32
	std::uint32_t pubsymflags;
	std::uint32_t off;
	std::uint16_t seg;
	char name[1];    // Length-prefixed name
};

enum { S_PUB32 = 0x110e };

struct CCodeViewInfo
{
	ULONG CvSignature;
	GUID Signature;
	ULONG Age;
	char PdbFileName[ANYSIZE_ARRAY];
};

auto CPdbParser::LocatePdbs(const std::vector<std::string>& PdbsToLocate) -> bool
{
	for (auto& PdbToLocate : PdbsToLocate)
	{
		if (!std::filesystem::exists(PdbToLocate))
			return false;

		std::vector<std::uint8_t> FileOnDisk;

		auto File = std::ifstream(PdbToLocate, std::ios::binary);
		FileOnDisk.assign(std::istreambuf_iterator(File), std::istreambuf_iterator<char>());
		File.close();

		const auto Headers = RtlImageNtHeader(FileOnDisk.data());
		if (!Headers)
			return false;

		const auto FileInMemory = std::make_unique<std::uint8_t[]>(Headers->OptionalHeader.SizeOfImage);
		const auto SectionHeaders = IMAGE_FIRST_SECTION(Headers);
		for (auto Index = 0; Index < Headers->FileHeader.NumberOfSections; ++Index)
		{
			if (SectionHeaders[Index].Characteristics & 0x800)
				continue;

			memcpy_s(FileInMemory.get() + SectionHeaders[Index].VirtualAddress, SectionHeaders[Index].SizeOfRawData, FileOnDisk.data() + SectionHeaders[Index].PointerToRawData, SectionHeaders[Index].SizeOfRawData);
		}

		const auto DebugDirectory = Headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		if (!DebugDirectory)
			return false;

		for (auto CurrentDebugDirectory = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(FileInMemory.get() + DebugDirectory); CurrentDebugDirectory->SizeOfData; CurrentDebugDirectory++)
		{
			if (CurrentDebugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;

			const auto CodeviewInfo = reinterpret_cast<CCodeViewInfo*>(FileOnDisk.data() + CurrentDebugDirectory->PointerToRawData);

			std::stringstream PdbExtentionPath;
			PdbExtentionPath << CodeviewInfo->PdbFileName << "\\";
			PdbExtentionPath << std::setfill('0') << std::setw(8) << std::hex << CodeviewInfo->Signature.Data1 << std::setw(4) << std::hex << CodeviewInfo->Signature.Data2 << std::setw(4) << std::hex << CodeviewInfo->Signature.Data3;
			for (const auto Signature : CodeviewInfo->Signature.Data4)
				PdbExtentionPath << std::setw(2) << std::hex << +Signature;
			PdbExtentionPath << "1\\" << CodeviewInfo->PdbFileName;

			const auto DownloadPath = std::filesystem::path(std::filesystem::temp_directory_path().string() + PdbExtentionPath.str());
			printf("%s\n", DownloadPath.string().c_str());
			if (!std::filesystem::exists(DownloadPath))
			{
				CreateDirectoryA((std::filesystem::temp_directory_path().string() + CodeviewInfo->PdbFileName).c_str(), nullptr);
				CreateDirectoryA(DownloadPath.string().substr(0, DownloadPath.string().find_last_of('\\')).c_str(), nullptr);

				constexpr auto SymbolServer = "http://msdl.microsoft.com/download/symbols/";
				if (URLDownloadToFileA(nullptr, (SymbolServer + PdbExtentionPath.str()).c_str(), DownloadPath.string().c_str(), 0, nullptr) != S_OK)
					return false;
			}

			this->Pdbs.emplace_back(DownloadPath.string(), PdbToLocate);
		}
	}

	return true;
}

auto GetStreamDirectory(void* Base) -> std::vector<std::uint8_t>
{
	std::vector<std::uint8_t> StreamDirectory;
	const auto Super = static_cast<SuperBlock*>(Base);
	const auto Size = Super->NumDirectoryBytes;
	const auto BlockSize = Super->BlockSize;

	const auto BlockCount = (Size + BlockSize - 1) / BlockSize;
	const auto BlockIdArray = reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(Base) + BlockSize * Super->BlockMapAddr);

	StreamDirectory.reserve(BlockCount * BlockSize);

	for (auto Index = 0u; Index < BlockCount; ++Index)
	{
		const auto Block = static_cast<std::uint8_t*>(Base) + BlockSize * BlockIdArray[Index];
		StreamDirectory.insert(StreamDirectory.end(), Block, Block + BlockSize);
	}

	StreamDirectory.resize(Size);
	return StreamDirectory;
}

auto GetStreams(void* Base) -> std::vector<std::vector<std::uint8_t>>
{
	std::vector<std::vector<std::uint8_t>> Streams;

	const auto Super = static_cast<SuperBlock*>(Base);
	const auto BlockSize = Super->BlockSize;

	auto StreamDirectory = GetStreamDirectory(Base);

	auto Ui32Iter = reinterpret_cast<std::uint32_t*>(StreamDirectory.data());

	const auto StreamNum = *Ui32Iter++;
	const auto StreamArray = Ui32Iter;
	Ui32Iter += StreamNum;

	Streams.reserve(StreamNum);

	for (auto StreamIndex = 0u; StreamIndex < StreamNum; ++StreamIndex)
	{
		std::vector<std::uint8_t> CurrentStream;

		const auto CurrentStreamSize = StreamArray[StreamIndex];
		const auto CurrentStreamBlockCount = (CurrentStreamSize + BlockSize - 1) / BlockSize;

		CurrentStream.reserve(CurrentStreamBlockCount * BlockSize);

		for (auto StreamBlockIndex = 0u; StreamBlockIndex < CurrentStreamBlockCount; ++StreamBlockIndex)
		{
			const auto BlockId = *Ui32Iter++;
			const auto Block = static_cast<uint8_t*>(Base) + BlockSize * BlockId;

			CurrentStream.insert(CurrentStream.end(), Block, Block + BlockSize);
		}

		CurrentStream.resize(CurrentStreamSize);
		Streams.push_back(std::move(CurrentStream));
	}

	return Streams;
}

auto GetTypesAndSymbols(void* Pdb) -> std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
{
	auto Streams = GetStreams(Pdb);
	const auto Types = Streams[2];
	const auto DbiHeader = reinterpret_cast<DBIHeader*>(Streams[3].data());
	const auto SymbolIndex = DbiHeader->SymRecordStream;
	const auto Symbols = Streams[SymbolIndex];

	return { Types, Symbols };
}

auto SymSectionToRva(std::vector<std::uint8_t> FileData, std::uint16_t SectionIndex, std::uint32_t SectionOffset) -> std::uint32_t
{
	if (!SectionIndex)
		return -1;

	SectionIndex -= 1;

	const auto Headers = RtlImageNtHeader(FileData.data());

	const auto SectionHeaders = IMAGE_FIRST_SECTION(Headers);
	if (SectionOffset > SectionHeaders[SectionIndex].Misc.VirtualSize)
		return -1;

	const auto SectionBase = SectionHeaders[SectionIndex].VirtualAddress;
	if (SectionBase + SectionOffset < SectionBase)
		return -1;

	return SectionBase + SectionOffset;
}

auto CPdbParser::LocateSymbol(const std::string& Function) -> std::uintptr_t
{
	for (auto& [PdbPath, FilePath] : this->Pdbs)
	{
		if (!std::filesystem::exists(PdbPath))
			continue;

		std::vector<std::uint8_t> PdbFileOnDisk;
		auto PdbFile = std::ifstream(PdbPath, std::ios::binary);
		PdbFileOnDisk.assign(std::istreambuf_iterator(PdbFile), std::istreambuf_iterator<char>());
		PdbFile.close();

		std::vector<std::uint8_t> FileOnDisk;
		auto File = std::ifstream(FilePath, std::ios::binary);
		FileOnDisk.assign(std::istreambuf_iterator(File), std::istreambuf_iterator<char>());
		File.close();

		auto [Types, Symbols] = GetTypesAndSymbols(PdbFileOnDisk.data());

		auto It = Symbols.data();
		const auto End = It + Symbols.size();
		while (It != End)
		{
			const auto Current = reinterpret_cast<PUBSYM32*>(It);
			if (Current->rectyp == S_PUB32)
			{
				if (std::string(reinterpret_cast<char*>(Current->name)) == Function)
					return SymSectionToRva(FileOnDisk, Current->seg, Current->off);
			}

			It += Current->reclen + 2;
		}
	}

	return 0;
}

auto CPdbParser::LocateSymbol(const std::string& FileName, const std::string& Function) -> std::uintptr_t
{
	std::string RealPdb{}, RealFile{};
	for (auto& [PdbPath, FilePath] : this->Pdbs)
		if (std::filesystem::path(FilePath).filename().string() == FileName)
		{
			RealPdb = PdbPath;
			RealFile = FilePath;
		}

	if (RealPdb.empty() || !std::filesystem::exists(RealPdb))
		return 0;

	std::vector<std::uint8_t> PdbFileOnDisk;
	auto PdbFile = std::ifstream(RealPdb, std::ios::binary);
	PdbFileOnDisk.assign(std::istreambuf_iterator(PdbFile), std::istreambuf_iterator<char>());
	PdbFile.close();

	std::vector<std::uint8_t> FileOnDisk;
	auto File = std::ifstream(RealFile, std::ios::binary);
	FileOnDisk.assign(std::istreambuf_iterator(File), std::istreambuf_iterator<char>());
	File.close();

	auto [Types, Symbols] = GetTypesAndSymbols(PdbFileOnDisk.data());

	auto It = Symbols.data();
	const auto End = It + Symbols.size();
	while (It != End)
	{
		const auto Current = reinterpret_cast<PUBSYM32*>(It);
		if (Current->rectyp == S_PUB32)
		{
			if (std::string(reinterpret_cast<char*>(Current->name)) == Function)
				return SymSectionToRva(FileOnDisk, Current->seg, Current->off);
		}

		It += Current->reclen + 2;
	}

	return 0;
}