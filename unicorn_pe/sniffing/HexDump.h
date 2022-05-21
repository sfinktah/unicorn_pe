#pragma once
// https://gist.github.com/kristopherjohnson/90581f20aab44e669907
// Copyright (C) 2015 Kristopher Johnson
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <ios>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <cctype>

#define DEBUG_HEXDUMP(NAME, PTR, LENGTH)                                \
    HexDump::dumpMemoryCallback(reinterpret_cast<char*>(PTR), (LENGTH), \
                                [&](std::string line, size_t offset) { LOG_FUNC(NAME "  %-18s: %s", "HexDump", line.c_str()); });

#define DEBUG_STRUCTDUMP(NAME, PTR, LENGTH) StructDump::toLog((PTR), (LENGTH), NAME);
//#include <vector>

namespace HexDump {

	using std::endl;
	using std::hex;
	using std::isprint;
	using std::left;
	using std::ostringstream;
	using std::setfill;
	using std::setw;
	using std::size_t;
	using std::vector;

	// In the templates below, the type parameters must satisfy these constraints:
	//
	// - Stream: something like std::ostream or std::istream
	//
	// - InputStream: something like std::istream
	//
	// - OutputStream: something like std::ostream
	//
	// - ByteSequence: a collection of chars that can be iterated over, like std::vector<char>

	static size_t BytesPerLine = 16;

	// Saves original formatting state for a stream and
	// restores that state before going out of scope
	template<typename Stream>
	class SavedState
	{
	public:
		SavedState(Stream& s)
			: stream(s), oldFlags(s.flags()), oldFill(s.fill())
		{}

		~SavedState() { stream.flags(oldFlags); stream.fill(oldFill); }

		SavedState(const SavedState&) = delete;
		void operator=(const SavedState&) = delete;

	private:
		Stream& stream;
		int oldFlags;
		char oldFill;
		//decltype(ofs.flags()) oldFlags;
		//decltype(ofs.fill()) oldFill;
	};

    template <typename T>
	auto peek(T ptr) {
        static void *exceptionAddress;
        __try {
            return *ptr;
        } __except (exceptionAddress = (GetExceptionInformation())->ExceptionRecord->ExceptionAddress, EXCEPTION_EXECUTE_HANDLER) {
        }
        return std::remove_pointer_t<T>{};
	}

	// Dump a sequence of bytes as hex with spaces between; e.g., "cf fa 4f a0 "
	template<typename OutputStream, typename ByteSequence>
	void dumpBytesAsHex(OutputStream& output, const ByteSequence& bytes, bool alternateSpaces = true)
	{
		SavedState<OutputStream> savedState{ output };

		output << hex << setfill('0');

        bool space = !alternateSpaces;
        for (auto byte : bytes) {
			unsigned widenedUIntValue = static_cast<unsigned char>(byte);
			output << setw(2) << widenedUIntValue << (space ? " " : "");
            space = space ^ alternateSpaces;
		}
	}

	// Dump a sequence of bytes as ASCII characters,
	// substituting '.' for non-printing characters
	template<typename OutputStream, typename ByteSequence>
	void dumpBytesAsText(OutputStream& output, const ByteSequence& bytes)
	{
        for (auto byte : bytes)
			output << (isprint((int)(uint8_t)byte) ? byte : '.');
	}

	// Dump a sequence of bytes in side-by-side hex and text formats
	template<typename OutputStream, typename ByteSequence>
	void dumpHexLine(OutputStream& output, const ByteSequence& bytes, bool text = true)
	{
		SavedState<OutputStream> savedState{ output };

		ostringstream hexStream;
		dumpBytesAsHex(hexStream, bytes);
		//const auto HexOutputWidth = Utility::clamp<int>(BytesPerLine, 0, 8) * 3 + 1;
		//output << setw(HexOutputWidth) << left << hexStream.str();
		output << setw(40) << left << setfill(' ') << hexStream.str();

        if (text) {
            output << ' ';
            dumpBytesAsText(output, bytes);
        }

        output << endl;
	}

	// Dump a sequence of bytes in side-by-side hex and text formats,
	// prefixed with a hex offset
	template<typename OutputStream, typename ByteSequence>
	void dumpHexLine(OutputStream& output, size_t offset, const ByteSequence& bytes)
	{
        // offset
		{
			SavedState<OutputStream> savedState{ output };
			output << setw(8) << setfill('0') << hex
			  	   << offset  << "  ";
		}

        // hex + ascii
        dumpHexLine(output, bytes);
	}

	// Dump a sequence of bytes in side-by-side hex and text formats,
	// prefixed with a hex offset
	template<typename ByteSequence>
	std::string dumpHexLine(size_t offset, const ByteSequence& bytes)
	{
        std::ostringstream oss;
		dumpHexLine(oss, offset, bytes);
        return oss.str();
	}

	// Dump bytes from input stream in side-by-side hex and text formats
	template<typename OutputStream, typename InputStream>
	void dumpStream(OutputStream& output, InputStream& input)
	{
		vector<char> bytesToDump;
		bytesToDump.reserve(BytesPerLine);

		size_t offset = 0;

		char byte;
		while (input.get(byte)) {
			bytesToDump.push_back(byte);

			if (bytesToDump.size() == BytesPerLine) {
				dumpHexLine(output, offset, bytesToDump);
				bytesToDump.clear();
				offset += BytesPerLine;
			}
		}

		if (!bytesToDump.empty())
			dumpHexLine(output, offset, bytesToDump);
	}

	// sfinktah - dump a freakin memory block, ffs, how hard is that
	template<typename OutputStream, typename Byte>
	void dumpMemory(OutputStream& output, Byte* address, size_t length)
	{
		vector<char> bytesToDump;
		bytesToDump.reserve(BytesPerLine);

		size_t offset = 0;

		while (length > 0 && length--) {
			char byte = peek(&address[offset++]);
			bytesToDump.push_back(byte);

			if (bytesToDump.size() == BytesPerLine) {
				dumpHexLine(output, offset - BytesPerLine, bytesToDump);
				bytesToDump.clear();
			}
		}

		if (!bytesToDump.empty())
			dumpHexLine(output, offset - bytesToDump.size(), bytesToDump);
	}

	template<typename Function>
	void dumpMemoryCallback(const void* _address, size_t length, Function onLine, size_t fake_offset = 0)
	{
        const char *address = reinterpret_cast<const char*>(_address);
		vector<char> bytesToDump;
		bytesToDump.reserve(BytesPerLine);

		size_t offset = 0;

        // needs crash protection
		while (length > 0 && length--) {
            char byte = peek(&address[offset++]);
			bytesToDump.push_back(byte);

			if (bytesToDump.size() == BytesPerLine) {
				std::string line = dumpHexLine(fake_offset + offset - BytesPerLine, bytesToDump);
                onLine(line, offset);
				bytesToDump.clear();
			}
		}

        if (!bytesToDump.empty()) {
            std::string line = dumpHexLine(fake_offset + offset, bytesToDump);
            onLine(line, offset);
        }
	}

    template<typename Byte>
    void toLog(Byte* _address, size_t length, const std::string& label) {
        dumpMemoryCallback(reinterpret_cast<const char*>(_address), length, [&](std::string line, size_t offset) {
            LOG_DEBUG("%-18s: %s", label.c_str(), line.c_str());
        });
    }

	template<typename Byte>
	std::string dumpMemory(Byte* address, size_t length)
	{
        std::ostringstream oss;
        dumpMemory(oss, address, length);
        return oss.str();
	}

	template<typename ByteSequence>
    std::string asString(const ByteSequence& bytes) {
        std::ostringstream oss;
        dumpBytesAsHex(oss, bytes, false);
        return oss.str();
        
    }

	template<typename Byte>
	std::string dumpMemoryAsString(const Byte* address, size_t length)
	{
        std::ostringstream oss;
        vector<char> bytesToDump(address, address + length);

        dumpBytesAsHex(oss, bytesToDump, false);
        return oss.str();
	}
} // namespace HexDump
