#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "pystring::pystring" for configuration "Release"
set_property(TARGET pystring::pystring APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(pystring::pystring PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/pystring.lib"
  )

list(APPEND _IMPORT_CHECK_TARGETS pystring::pystring )
list(APPEND _IMPORT_CHECK_FILES_FOR_pystring::pystring "${_IMPORT_PREFIX}/lib/pystring.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
