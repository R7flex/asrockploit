#pragma once
#include <string>
#include <vector>

class CPdbParser
{
public:
	CPdbParser() = default;

	auto LocatePdbs(const std::vector<std::string>& PdbsToLocate) -> bool;
	auto LocateSymbol(const std::string& Function)->std::uintptr_t;
	auto LocateSymbol(const std::string& FileName, const std::string& Function)->std::uintptr_t;

private:
	std::vector<std::pair<std::string, std::string>> Pdbs{};
};

inline CPdbParser pdb_parser{};