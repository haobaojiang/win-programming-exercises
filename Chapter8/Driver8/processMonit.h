#pragma once

namespace ProcessMonit {

	NTSTATUS Add(PCWCHAR KeyName);

	void Remove(PCWCHAR KeyName);

	void Clear();

	BOOLEAN Find(PCUNICODE_STRING KeyName);

	// call by DriverEntry
	BOOLEAN Initialize();

	// call by DriverUnload
	VOID Finiallize();
}