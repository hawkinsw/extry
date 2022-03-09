#include <algorithm>
#include <extry/extry.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elf.h>
#include <libelf.h>

bool Extry::load(const std::string &load_filename, std::string &err_message) {
  Elf_Scn *scn_iterator{nullptr};

  Elf_Scn *string_scn{nullptr};
  Elf_Data *string_data{nullptr};

  if ((m_elf_fd = open(load_filename.c_str(), O_RDWR)) < 0) {
    std::cerr << (err_message = "Could not open the requested ELF file.");
    return false;
  }

  elf_version(EV_CURRENT);
  m_elf_handle = elf_begin(m_elf_fd, ELF_C_RDWR, nullptr);

  if (!m_elf_handle) {
    close(m_elf_fd);
    std::cerr << (err_message =
                      "Could not create an ELF handle for the ELF file.");
    return false;
  }

  /* Obtain the .shstrtab data buffer */
  if (((m_ehdr = elf64_getehdr(m_elf_handle)) == nullptr) ||
      ((string_scn = elf_getscn(m_elf_handle, m_ehdr->e_shstrndx)) ==
       nullptr) ||
      ((string_data = elf_getdata(string_scn, nullptr)) == nullptr)) {
    elf_end(m_elf_handle);
    close(m_elf_fd);
    std::cerr << (err_message = "Could not find the string header.");
    return false;
  }

  m_entry_point = m_ehdr->e_entry;

  if (m_debug) {
    std::cout << "Discovered an entry point at 0x" << std::hex << m_entry_point
              << std::dec << "\n";
  }

  /* Traverse input filename, printing each section */
  while ((scn_iterator = elf_nextscn(m_elf_handle, scn_iterator))) {
    Elf64_Shdr *shdr{nullptr};
    if ((shdr = elf64_getshdr(scn_iterator)) == NULL) {
      elf_end(m_elf_handle);
      close(m_elf_fd);
      std::cerr << (err_message =
                        "Failed to iterate through the section headers.");
      return false;
    }

    if (shdr->sh_addr <= m_entry_point &&
        m_entry_point < (shdr->sh_addr + shdr->sh_size)) {
      m_entry_section_data = elf_getdata(scn_iterator, nullptr);
      m_entry_section_name =
          std::string{(char *)string_data->d_buf + shdr->sh_name};
      m_entry_section_hdr = shdr;
      m_entry_section = scn_iterator;
      if (m_debug) {
        std::cout << "Found the entry point in the " << m_entry_section_name
                  << " section.\n";
      }
      break;
    }
  }

  if (!m_entry_section) {
    elf_end(m_elf_handle);
    close(m_elf_fd);
    std::cerr << (err_message = "Could not find the program section!");
    return false;
  }

  if (m_debug) {
    std::cout << "Initialization of Extry complete.\n";
  }

  m_loaded = true;
  return true;
}

Extry::~Extry() {
  if (m_loaded) {
    elf_end(m_elf_handle);
    close(m_elf_fd);
  }
}

bool Extry::rewrite(std::string &err_message) {
  /*
   * We are just going to do the simple thing now -- put a ret and bombs away.
   */

  // Let's do a sanity check first!
  int64_t potential_data_buffer_offset = static_cast<int64_t>(m_entry_point) - m_entry_section_hdr->sh_addr;
  if (potential_data_buffer_offset < 0 || potential_data_buffer_offset > m_entry_section_hdr->sh_size) {
    err_message = "Attempting to update at an entry point that is invalid.";
    return false;
  }
  uint64_t data_buffer_offset = m_entry_point - m_entry_section_hdr->sh_addr;

  *(uint8_t*)(((uint8_t*)m_entry_section_data->d_buf) + data_buffer_offset) = 0xc3;

  if (!elf_flagdata(m_entry_section_data, ELF_C_SET, ELF_F_DIRTY)) {
    err_message = "Attempting to update at an entry point that is invalid.";
    return false;
  }
  return true;
}

bool Extry::save(std::string &err_message) {
  int elf_update_result{-1};
  if ((elf_update_result = elf_update(m_elf_handle, ELF_C_WRITE)) < 0) {
    err_message = std::string{elf_errmsg(-1)};
    return false;
  }
  if (m_debug) {
    std::cout << "Updated an ELF file with " << elf_update_result << " bytes.\n";
  }
  return true;
}
