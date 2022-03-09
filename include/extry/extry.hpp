/*
 *    This file is part of Extry.
 *
 *    Extry is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 *    Extry is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 * with Extry. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _EXTRY_EXTRY_HPP
#define _EXTRY_EXTRY_HPP

#include <elf.h>
#include <libelf.h>
#include <stdint.h>
#include <string>

class Extry {
public:
  enum class ExtryType {
    Random,
    Stop,
    Infinite,
  };

  Extry(ExtryType extry_type, bool debug = false)
      : m_extry_type(extry_type), m_entry_point(0), m_debug(debug),
        m_loaded(false), m_elf_fd(0), m_elf_handle(nullptr),
        m_ehdr(nullptr), m_entry_section_name(""), m_entry_section(nullptr),
        m_entry_section_data(nullptr) {
  }

  bool load(const std::string &load_filename, std::string &err_message);
  bool rewrite(std::string &err_message);
  bool save(std::string &err_message);

  ~Extry();

private:
  ExtryType m_extry_type;
  uint64_t m_entry_point;
  bool m_debug, m_loaded;
  int m_elf_fd;
  Elf *m_elf_handle;
  Elf64_Ehdr *m_ehdr{nullptr};
  Elf64_Shdr *m_entry_section_hdr{nullptr};
  std::string m_entry_section_name;
  Elf_Scn *m_entry_section;
  Elf_Data *m_entry_section_data;
};

#endif
