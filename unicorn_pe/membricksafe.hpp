#pragma once

/*
 *           _
 * __  _ __ |_) __ o  _  |
 * |||(/_||||_) |  | (_  |<
 *
 */

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <valarray>
#include <type_traits>
#include <vector>
#include <forward_list>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include "ucpe.h"
//#include "encrypted_string.h"

// static std::string _substr(const std::string& s, size_t pos, size_t npos) { return s.substr(pos, npos); }
//#include <cstdlib>
//#include <initializer_list>
//#include <valarray>
//#include <cstdint>
//#include <cstring>
//#include <type_traits>
//#include <windows.h>
//#include <cstddef> // for std::size_t (well that was the theory)
//#include <climits>
//#include <stdexcept>
//#include <typeinfo>
//#include <locale>

static int exceptionFilter(unsigned int code, struct _EXCEPTION_POINTERS* ep) {
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static bool mb_isStringSafeFast(const char* st) {
    if (!st) return 0;
    // stupid m$ exceptions: https://msdn.microsoft.com/en-us/library/s58ftw19.aspx
    __try {
        for (const char* p = st; p++;)
            if (*p < 32 && *p != 0x0d && *p != 0x0a && *p != 0x09)
                // will return 1 if \x00 is found
                return !*p;
    } __except (exceptionFilter(GetExceptionCode(), GetExceptionInformation())) {
    }
    return 0;
    // If we didn't see a \x00 then it's not a safe string people!
}

static const char* mb_safeString(const char* s, const char* defaultString) {
    const char* error = nullptr;
    return mb_isStringSafeFast(s) ? s : defaultString;
}

struct PATCH_ENTRY {
    static std::unordered_map<std::string, PATCH_ENTRY&> patchlist;
    PATCH_ENTRY(const char* name) : name(name), pTarget(0), isEnabled(false), dontRemove(false), checkData(false) {
        patchlist.emplace(name, *this);
    };
    std::string name;  // only populated in dev builds
    uintptr_t pTarget;    // Address of the target function.
    std::vector<BYTE> original, patched;
    bool isEnabled : 1;   // Enabled.
    bool dontRemove : 1;  // Don't remove during unload
    bool checkData : 1;
    void disable() {
        if (isEnabled) {
            if (!checkData || doublecheck()) {
                uc_memcpy(g_ctx.m_uc, pTarget, original.data(), original.size());
            }
            isEnabled = false;
        }
    }
    void enable() {
        if (!isEnabled) {
            uc_memcpy(g_ctx.m_uc, pTarget, patched.data(), patched.size());
            isEnabled = true;
        }
    }
    void enable(bool _) { return _ ? enable() : disable(); }
    bool doublecheck() { return !uc_memcmp(g_ctx.m_uc, pTarget, patched.data(), patched.size()); }

    bool enabled() { return isEnabled; }
};

typedef PATCH_ENTRY* PPATCH_ENTRY;

namespace membricksafe {

    // Hook entries.
    extern std::forward_list<PATCH_ENTRY> g_patches;

    template <class ConcreteBrick>
    class memBrickBase {
    protected:
        void* _handle;
        const char* _pattern;
        void* handle() const { return _handle; }
        void handle(void* _) { _handle = _; }

    public:
        typedef ConcreteBrick R;

    public:
        memBrickBase() : _handle(nullptr) {}

        memBrickBase(void* p) : _handle(p) {}

        memBrickBase(std::uintptr_t p) : _handle(reinterpret_cast<void*>(p)) {}

        memBrickBase(const memBrickBase& copy) : _handle(copy._handle) {}

        static R scan(memBrickBase base, std::size_t size, const char* pattern) {
            struct nibble {
                std::uint8_t value  = 0;
                std::uint8_t offset = 0;
            } nibbles[128];

            std::size_t count = 0;

            for (; pattern; pattern = std::strpbrk(pattern, " ")) {
                pattern += std::strspn(pattern, " ");  // Discard whitespace

                if (pattern[0] != '?') {
                    nibbles[count].value      = std::uint8_t(std::strtol(pattern, nullptr, 16));
                    nibbles[count + 1].offset = nibbles[count].offset;

                    count++;
                }

                nibbles[count].offset++;
            }

            if (!size) size = nibbles[count].offset + 1;
            for (std::size_t i = 0, end = size - nibbles[count].offset; i < end; i++) {
                R currentOffset = base.offset(i);

                bool found = true;

                for (std::size_t j = 0; j < count; ++j) {
                    if (nibbles[j].value != currentOffset.offset(nibbles[j].offset).read<std::uint8_t>()) {
                        found = false;

                        break;
                    }
                }

                if (found) {
                    return currentOffset;
                }
            }

            return nullptr;
        }

        template <typename T>
        std::enable_if_t<std::is_pointer<T>::value, T> as() const {
            return reinterpret_cast<T>(this->_handle);
        }

        template <typename T>
        std::enable_if_t<std::is_lvalue_reference<T>::value, T> as() const {
            return *reinterpret_cast<std::remove_reference_t<T>*>(this->_handle);
        }

        template <typename T>
        std::enable_if_t<std::is_array<T>::value, T&> as() const {
            return *reinterpret_cast<T*>(this->_handle);
        }

        template <typename T>
        std::enable_if_t<std::is_same<T, std::uintptr_t>::value, T> as() const {
            return reinterpret_cast<std::uintptr_t>(this->_handle);
        }

        template <typename T>
        std::enable_if_t<std::is_same<T, std::intptr_t>::value, T> as() const {
            return reinterpret_cast<std::intptr_t>(this->_handle);
        }

        operator bool() const { return (this->as<void*>() != nullptr); }

        template <typename T>
        T read() const {
            return *this->as<T*>();
        }

        bool matches(const char* pattern) {
            auto mb = scan(_handle, 0, pattern);
            return mb.good();
        }

        R save(memBrickBase& out) const { return (out = *this); }

        R offset(std::intptr_t offset) const { return this->as<std::uintptr_t>() + offset; }
        R add(std::intptr_t offset) const { return this->offset(offset); }

        R unprotect(std::size_t size = 64) {
            std::uint32_t oldProtect;
            this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect);
            return _handle;
        }

        R rip(std::uintptr_t ipoffset) const { return this->offset(ipoffset).offset(this->read<int>()); }

        R translate(memBrickBase from, memBrickBase to) const {
            return to.offset(this->as<std::intptr_t>() - from.as<std::intptr_t>());
        }

        bool protect(std::size_t size, std::uint32_t newProtect, std::uint32_t* oldProtect) {
            if (oldProtect) *oldProtect = newProtect;
			return true;
            //return VirtualProtect(this->as<void*>(), size, (DWORD)newProtect, (DWORD*)oldProtect) == TRUE;
        }

        R nop(std::size_t count) {
			const unsigned char nop_bytes[][8] = {
				{},
				{0x90},
				{0x66, 0x90},
				{0x0f, 0x1f, 0x00},
				{0x0f, 0x1f, 0x40, 0x00},
				{0x0f, 0x1f, 0x44, 0x00, 0x00},
				{0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
				{0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
				{0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
			};

			uc_err err = UC_ERR_OK;
			uintptr_t address = this->as<uintptr_t>();
			while (err == UC_ERR_OK && count) {
				size_t size = count > 8 ? 8 : count;
				err         = uc_memcpy(g_ctx.m_uc, address, nop_bytes[size], size) ? UC_ERR_OK : UC_ERR_EXCEPTION;
				count       = count - size;
				address     = address + size;
			}
            return _handle;
        }

        R nop(std::size_t size, PATCH_ENTRY patch) {
            // LOG_DEBUG("Noppin: %p", this->as<void*>());
            char* p = this->as<char*>();
            // http://stackoverflow.com/a/261607/912236
            patch.original.insert(patch.original.end(), &p[0], &p[size]);
            patch.pTarget   = this->as<void*>();
            patch.isEnabled = 1;
            nop(size);
            patch.patched.insert(patch.patched.end(), &p[0], &p[size]);
            g_patches.emplace_front(std::move(patch));
            // return &g_patches.front();
            return _handle;
        }

        template <typename T>
        void write(T value) {
            static_assert(std::is_trivially_copyable<T>::value, "Type is not trivially copyable");
            uc_memcpy(g_ctx.m_uc, this->as<uintptr_t>(), &value, sizeof T);
            // this->write<T>(value);
        }

        template <typename T>
        PPATCH_ENTRY write(T value, PATCH_ENTRY patch) {
            char* p = this->as<char*>();
            // http://stackoverflow.com/a/261607/912236
            patch.pTarget   = this->as<uintptr_t>();
            patch.isEnabled = 1;
            patch.original.insert(patch.original.end(), &p[0], &p[sizeof(T)]);

            this->write<T>(value);

            patch.patched.insert(patch.patched.end(), &p[0], &p[sizeof(T)]), g_patches.emplace_front(std::move(patch));
            return &g_patches.front();
        }

        R call() const { return offset(1).rip(4); }

        // template, or implement for multiple argument types
        R call(const uintptr_t func) {
            // surely not the best way to do it, but whatever
            this->write<uint8_t>(0xe8);
            this->offset(1).write<int>(func - this->as<uintptr_t>() - 5);
            return this->_handle;
        }

        R jmp(const uintptr_t func) {
            this->write<uint8_t>(0xe9);
            this->offset(1).write<int>(func - this->as<uintptr_t>() - 5);
            return this->_handle;
        }

        // template, or implement for multiple argument types
        R call(void* func) {
            this->write<uint8_t>(0xe8);
            this->offset(1).write<int>(reinterpret_cast<uintptr_t>(func) - this->as<uintptr_t>() - 5);
            return this->_handle;
        }

        R jmp(void* func) {
            this->write<uint8_t>(0xe9);
            this->offset(1).write<int>(reinterpret_cast<uintptr_t>(func) - this->as<uintptr_t>() - 5);
            return this->_handle;
        }

        PPATCH_ENTRY jmp_pe(void* func, PATCH_ENTRY patch) {
            char* p = this->as<char*>();
            // http://stackoverflow.com/a/261607/912236
            patch.pTarget   = this->as<void*>();
            patch.isEnabled = 1;
            patch.original.insert(patch.original.end(), &p[0], &p[5]);

            this->write<uint8_t>(0xe9);
            // this->offset(1).write<int>(reinterpret_cast<uintptr_t>(func) - _handle - 5)

            // put<int>((uintptr_t)this->as<uintptr_t>() + 1, (intptr_t)funcstub - (intptr_t)get_adjusted(this->as<uintptr_t>()) - 5);
            this->offset(1).write<int>((intptr_t)func - (intptr_t)_handle - 5)

            patch.patched.insert(patch.patched.end(), &p[0], &p[5]), g_patches.emplace_front(std::move(patch));
            return &g_patches.front();
        }

        template <typename T>
        PPATCH_ENTRY write_vp(T value, PATCH_ENTRY patch) {
            std::uint32_t oldProtect;

            auto size = sizeof(value);

            if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                this->write(value, patch);

                this->protect(size, oldProtect, nullptr);

                return true;
            }

            return false;
        }

        template <typename... T>
        R write_args(T... args) {
            std::uintptr_t off = 0;

            ((this->offset(off).write(args), off += sizeof(args)), ...);
            return this->as<std::uintptr_t>();
            return this->_handle;
        }

        PPATCH_ENTRY write_pattern_pe(PPATCH_ENTRY patch, const char* pattern) {
            std::uint8_t bytes[128];
            std::size_t count = 0;

            for (; pattern; pattern = std::strpbrk(pattern, " ")) {
                pattern += std::strspn(pattern, " ");  // Discard whitespace
                bytes[count] = std::uint8_t(std::strtol(pattern, nullptr, 16));
                count++;
            }

            if (patch) {
                patch->pTarget   = this->as<void*>();
                patch->isEnabled = 1;
            }
            char* p;
            for (std::size_t i = 0; i < count; ++i) {
                p = this->offset(i).as<char*>();
                if (patch) patch->original.insert(patch->original.end(), &p[0], &p[1]);
                this->offset(i).write<std::uint8_t>(bytes[i]);
                if (patch) patch->patched.insert(patch->patched.end(), &p[0], &p[1]);
            }

            if (patch) {
                g_patches.emplace_front(std::move(*patch));
                return &g_patches.front();
            }
            return patch;  // nullptr
        }

        R write_pattern(const char* pattern) {
            this->write_pattern_pe(nullptr, pattern);
            return this->_handle;
        }

        R memcpy(const void* src, size_t size) {
            uc_memcpy(g_ctx.m_uc, this->as<uintptr_t>(), src, size);
            return this->_handle;
        }

        PPATCH_ENTRY write_pattern_pe(PATCH_ENTRY patch, const char* pattern) { return this->write_pattern_pe(&patch, pattern); }

        template <typename T>
        PPATCH_ENTRY write_args_pe(PATCH_ENTRY patch, const std::initializer_list<T>& list) {
            std::uintptr_t off = 0;
            patch.pTarget      = this->as<void*>();
            patch.isEnabled    = 1;
            char* p;
            for (const auto& i : list) {
                p = this->offset(off).as<char*>();
                patch.original.insert(patch.original.end(), &p[0], &p[sizeof(T)]), this->offset(off).write<T>(i);
                patch.patched.insert(patch.patched.end(), &p[0], &p[sizeof(T)]), off += sizeof(T);
            }

            g_patches.emplace_front(std::move(patch));
            return &g_patches.front();
        }

#define ZORG_BROXED_WRITE_ARGS
#ifdef ZORG_BROXED_WRITE_ARGS
        template <typename... T>
        PPATCH_ENTRY write_args_pe(PATCH_ENTRY patch, T... args) {
            std::uintptr_t off = 0;
            patch.pTarget      = this->as<void*>();
            patch.isEnabled    = 1;

            char* p;
            ((p = this->offset(off).as<char*>(), patch.original.insert(patch.original.end(), p, p + sizeof(args)),
              this->offset(off).write<T>(args), patch.patched.insert(patch.patched.end(), p, p + sizeof(args)),
              off += sizeof(args)),
             ...);
            g_patches.emplace_front(std::move(patch));
            return &g_patches.front();

            //				this->protect(size, oldProtect, nullptr);
        }
#else
        template <typename... T>
        PPATCH_ENTRY write_args_pe(PATCH_ENTRY patch, T... args) {
            std::uintptr_t off = 0;
            patch.pTarget      = this->as<void*>();
            patch.isEnabled    = 1;
            char* p;
            (void)std::initializer_list<uint64_t>{
                0, (p = this->offset(off).as<char*>(), patch.original.insert(patch.original.end(), p, p + sizeof(args)),
                    this->offset(off).write<T>(args), patch.patched.insert(patch.patched.end(), p, p + sizeof(args)),
                    off += sizeof(args))...};
            g_patches.emplace_front(std::move(patch));
            return &g_patches.front();
        }
#endif

        template <typename T>
        bool write_vp(T value) {
            std::uint32_t oldProtect;

            auto size = sizeof(value);

            if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                this->write(value);

                this->protect(size, oldProtect, nullptr);

                return true;
            }

            return false;
        }

        template <typename... T>
        bool write_args_vp(T... args) {
            std::uint32_t oldProtect;

            auto size = std::valarray<std::size_t>({sizeof(args)...}).sum();

            if (this->protect(size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                this->write_args(args...);

                this->protect(size, oldProtect, nullptr);

                return true;
            }

            return false;
        }
    };

    class memBrick : public memBrickBase<memBrick> {
    public:
        memBrick() { handle(nullptr); }
        memBrick(void* p) { handle(p); }
        memBrick(std::uintptr_t p) : memBrick(reinterpret_cast<void*>(p)){};
        memBrick(const memBrick& copy) : memBrick(copy.handle()){};
        // { handle(copy.handle()); }
    };

    // http://stackoverflow.com/questions/8152720/correct-way-to-inherit-from-stdexception

    class memBrick_error : public ::std::exception {
    public:
        typedef ::std::exception BASECLASS;
        explicit memBrick_error() : BASECLASS() {}
        explicit memBrick_error(const ::std::string& what) : BASECLASS(what.c_str()) {}
        explicit memBrick_error(const char* what) : BASECLASS(what) {}
    };

    constexpr const bool _useExceptions = true;
    class memBrickSafe : public memBrickBase<memBrickSafe> {

    protected:
        memBrickSafe errorFatal(std::string msg = "") const {
            if (_useExceptions) {
                throw memBrick_error(msg);
            }
            return memBrickSafe(nullptr);
        }

    public:
        memBrickSafe() : memBrickBase(nullptr) {}
        memBrickSafe(void* p) : memBrickBase(p) { will_derefence(); }
        memBrickSafe(std::uintptr_t p) : memBrickBase(p) { will_derefence(); }
        memBrickSafe(const memBrickSafe& copy) : memBrickBase(static_cast<memBrickBase>(copy)) { will_derefence(); }

        bool isNull() const { return _handle == nullptr; }
        bool good() const { return _handle != nullptr; }

        static memBrickSafe scan(memBrick base, std::size_t size, const char* pattern, const char* name = nullptr) {
            memBrickSafe result = memBrick::scan(base, size, pattern);
            return result.good() ? result : result.errorFatal(std::string("Failed to find pattern ") + (name ? name : ""));
        }

        //static memBrickSafe scan(MODULEINFO module, const char* pattern, const char* name = nullptr) {
        //    return memBrickSafe::scan(module.lpBaseOfDll, module.SizeOfImage, pattern, name);
        //}

        template <typename T>  // this->as<const char*>(); Doesn't dereference, nullptr safe.
        std::enable_if_t<std::is_pointer<T>::value, T> as() const {
            return reinterpret_cast<T>(this->_handle);
        }

        void* will_derefence() const { return good() ? this->_handle : (this->errorFatal(), nullptr); }

        template <typename T>  // this->as<DWORD&>();
        std::enable_if_t<std::is_lvalue_reference<T>::value, T> as() const {
            return *reinterpret_cast<std::remove_reference_t<T>*>(will_derefence());
            // return *reinterpret_cast<std::remove_reference_t<T>*>(this->handle);
        }

        template <typename T>
        std::enable_if_t<std::is_array<T>::value, T&> as() const {
            return *reinterpret_cast<T*>(will_derefence());
            // return *reinterpret_cast<T*>(this->_handle);
        }

        template <typename T>  // nullptr safe
        std::enable_if_t<std::is_same<T, std::uintptr_t>::value, T> as() const {
            return reinterpret_cast<std::uintptr_t>(this->_handle);
        }

        template <typename T>  // nullptr safe
        std::enable_if_t<std::is_same<T, std::intptr_t>::value, T> as() const {
            return reinterpret_cast<std::intptr_t>(this->_handle);
        }

        template <typename T>
        T read() const {
            will_derefence();
            return *this->as<T*>();
        }

        template <typename T>
        std::string str() const {
            will_derefence();
            return mb_safeString(*this->as<LPSTR*>(), "");
        }

        // memBrickSafe offset(std::intptr_t offset) const
        //{
        //    return this->as<std::uintptr_t>() + offset;
        //}

        // memBrickSafe rip(std::uintptr_t ipoffset) const
        //{
        //    return this->offset(ipoffset).offset(this->read<int>());
        //}

        // BASIC_STRING_TEMPLATE
        //    memBrickSafe autorip(CREF_BASIC_STRING pattern_, size_t count = 0) const {
        //    size_t pos = 0, found = 0;
        //    while (found < count + 1) {
        //        size_t qp = pattern_.find("?? ?? ?? ??", pos ? pos + 11 : 0);
        //        if (qp == std::string::npos)
        //            return errorFatal("offset not found in pattern");
        //        ++found, pos = qp;
        //    }
        //    return (static_cast<memBrickSafe>(offset(pos / 3))).rip(4);
        //}

        memBrickSafe autorip(const char* pattern_, size_t count = 0) const {
            size_t pos = 0, found = 0;
            const char* pattern_ptr = pattern_;
            while (found < count + 1) {
                pattern_ptr = strstr(pattern_ptr, "?? ?? ?? ??");
                if (!pattern_ptr) return errorFatal("offset not found in pattern");
                ++found, pos = pattern_ptr - pattern_;
                // LOG_DEBUG(__FUNCTION__ ": count(%Zi): offset(%Zi): %s", count, pos, _substr(pattern_, pos, 14).c_str());
                pattern_ptr += 11;
            }
            return (static_cast<memBrickSafe>(offset(pos / 3))).rip(4);
        }
    };

    // memBrickSafe SafeScan(const char* pattern, DWORD patternHash = 0);
    // template <typename T>
    memBrickSafe SafeScan(const char* pattern, const char* identifier);
}  // namespace membricksafe
