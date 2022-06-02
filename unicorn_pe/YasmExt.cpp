#include <string>
#include <cstdint>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <fmt/format.h>
#include <pystring/pystring.h>
#include "TemporaryFile.h"
#include "util.hpp"
#include "lodash/121_times.h"
#include "lodash/026_slice.h"
#include "FileUtils.h"
#include "sniffing/HexDump.h"
#include <io.h>

#include "YasmExt.h"

std::string YasmExt::get_error() {
    return "";
}
std::vector<uint8_t> YasmExt::get_assembled() {
    return {};
}

bool YasmExt::prep() {
    // have to align nasm on on a 4byte paragraph or it does alignment thing
    std::vector<std::string> input;

    auto ea          = origin;
    auto adjusted_ea = ea & ~0x3;
    auto shift       = ea - adjusted_ea;

    // if isinstance(string, list): string = '\n'.join(string)

    auto string = pystring::replace(asmSource, "\r", "");

    input.emplace_back(fmt::format("[org {:#x}]", adjusted_ea));
    input.emplace_back("[bits 64]");
    _::timesSimple(shift, [&] {
        input.emplace_back("nop");
    });

    std::vector<std::string> lines;
    pystring::splitlines(string, lines);
    for (const std::string& line : lines) {
        input.emplace_back(line);
    }

    auto asmSource = pystring::join("\n", input);
    //  asmSource = asmSource.replace(' xmmword ', ' oword ')

    TemporaryFile asmFile;
    TemporaryFile objFile;

    file_put_contents(asmFile, asmSource.c_str(), asmSource.size());

    auto retry = 2;
    while (retry--) {

        int errorlevel;
        std::string output;
        auto result = assemble(asmFile, objFile, output, errorlevel);
        LOG("assemble: result: {}, errorlevel: {}, output: {}",
            result, errorlevel, output);
        if (result && file_exists(objFile)) {
            auto o = file_get_contents_bin(objFile);
            if (auto length = o.size()) {
                auto assembled = _::slice(o, shift);
                HexDump::dumpBytesAsHex(*outs, assembled);
                *outs << std::endl;
            }
            return true;
        }

        if (output.size()) {
            std::vector<std::string> errors;
            pystring::splitlines(string, lines);
            for (const std::string& line : lines) {
                // lineno, level, message

                std::vector<std::string> matches;
                if (preg_match(R"(^(?:.*):(\d+): (\w+): (.*))", output, &matches)) {
                    auto lineno  = matches[1];
                    auto level   = matches[2];
                    auto message = pystring::strip(matches[3]);

                    if (~pystring::find(message, "(Each undefined symbol is reported only once.)"))
                        continue;

                    auto error_display_str = fmt::format("{:8} {:3} {} {:18} {}", level, lineno, message, "", input[parseInt(lineno, 10) - 1]);
                    auto error_store_str   = fmt::format("{}: {} ({})", level, message, input[parseInt(lineno, 10) - 1]);
                    errors.emplace_back(error_store_str);
                    LOG("nasm error: {}", error_display_str);
                    //  print("fn, lineno, level, message", fn, lineno, level, message)
                }
                if (preg_match(R"(undefined symbol `([^"]+))", output, &matches)) {
                    auto sym = matches[1];
                    LOG("Couldn't find address of {}", sym);
                }

                if (!retry) {
                    LOG("Failed to assemble at {:x}: {}", ea, string);
                }
            }
        }
    }
    return false;
}

bool YasmExt::assemble(const std::string& filename, const std::string& objname, std::string& output, int& errorlevel) {
    char psBuffer[128];

	yasmPath = GetOurExeFolder("yasm.exe");

    /* Run DIR so that it writes its output to a pipe. Open this
         * pipe with read text attribute so that we can read it
         * like a text file.
         */
    FILE* pPipe;
    // pPipe = pPipe = _popen(fmt::format("{} --machine=amd64 --objfile={} --force-strict -P \"{}\" \"{}\"", yasmPath, objPath, preInclude, asmPath).c_str(), "rt");
    auto cmd = fmt::format("{} --machine=amd64 --objfile=\"{}\" --force-strict \"{}\" 2>&1", yasmPath, objname, filename);

    // LOG("cmd: {}", cmd);
	pPipe = pPipe = _popen(cmd.c_str(), "rt");

    if (!pPipe) {
		LOG("popen failed");
        return false;
	}

    /* Read pipe until end of file, or an error occurs. */

    while (fgets(psBuffer, 128, pPipe)) {
        output += psBuffer;
    }

    /* Close pipe and print return value of pPipe. */
    if (feof(pPipe)) {
		errorlevel = _pclose(pPipe);
		return errorlevel == 0;
    } else {
        printf("Error: Failed to read the pipe to the end.\n");
		return false;
    }
}

YasmExt::YasmExt(const std::string& string, uintptr_t origin) {
    //asmPath = tmpname)
	this->asmSource = string;
    this->origin = origin;
}

//input.insert(0, fmt::format("[org 0x{:x}]", adjusted_ea)
//input.insert(0, fmt::format("[bits {}]", options.get('bits', '64'))

// crt_popen.c
/* This program uses _popen and _pclose to receive a
* stream of text from a system process.
*/
