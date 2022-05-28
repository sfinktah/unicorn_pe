#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "pystring::pystring" for configuration "Debug"
set_property(TARGET pystring::pystring APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(pystring::pystring PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/pystring.lib"
  )

list(APPEND _IMPORT_CHECK_TARGETS pystring::pystring )
list(APPEND _IMPORT_CHECK_FILES_FOR_pystring::pystring "${_IMPORT_PREFIX}/debug/lib/pystring.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
