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

#include "Zydis/Encoder.h"
#include "Zydis/SharedTypes.h"
#include <algorithm>
#include <extry/extry.hpp>
#include <iostream>
#include <random>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

#include <fcntl.h>
#include <memory.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <Zydis/Zydis.h>
#include <elf.h>
#include <libelf.h>

bool Extry::load(const std::string &load_filename, std::string &err_message) {
  Elf_Scn *scn_iterator{nullptr};

  Elf_Scn *string_scn{nullptr};
  Elf_Data *string_data{nullptr};

  if ((m_elf_fd = open(load_filename.c_str(), O_RDWR)) < 0) {
    err_message = "Could not open the requested ELF file.";
    return false;
  }

  // Generally helpful libELF information:
  // https://bugzilla.redhat.com/show_bug.cgi?id=1273250
  elf_version(EV_CURRENT);
  m_elf_handle = elf_begin(m_elf_fd, ELF_C_RDWR, nullptr);

  if (!m_elf_handle) {
    close(m_elf_fd);
    err_message = "Could not create an ELF handle for the ELF file.";
    return false;
  }

  /* Obtain the .shstrtab data buffer */
  if (((m_ehdr = elf64_getehdr(m_elf_handle)) == nullptr) ||
      ((string_scn = elf_getscn(m_elf_handle, m_ehdr->e_shstrndx)) ==
       nullptr) ||
      ((string_data = elf_getdata(string_scn, nullptr)) == nullptr)) {
    elf_end(m_elf_handle);
    close(m_elf_fd);
    err_message = "Could not find the string header.";
    return false;
  }

  m_entry_point = m_ehdr->e_entry;

  if (m_debug) {
    std::cout << "Discovered an entry point at 0x" << std::hex << m_entry_point
              << std::dec << "\n";
  }

  while ((scn_iterator = elf_nextscn(m_elf_handle, scn_iterator))) {
    Elf64_Shdr *shdr{nullptr};
    if ((shdr = elf64_getshdr(scn_iterator)) == NULL) {
      elf_end(m_elf_handle);
      close(m_elf_fd);
      err_message = "Failed to iterate through the section headers.";
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
    err_message = "Could not find the program section!";
    return false;
  }

  if (m_debug) {
    std::cout << "Initialization of Extry complete.\n";
  }

  // https://stackoverflow.com/questions/10945239/trouble-using-libelf-elfio-libraries-elf-not-executable-anymore
  elf_flagelf(m_elf_handle, ELF_C_SET, ELF_F_LAYOUT);

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

  // Let's do a sanity check first!
  int64_t potential_data_buffer_offset =
      static_cast<int64_t>(m_entry_point) - m_entry_section_hdr->sh_addr;
  if (potential_data_buffer_offset < 0 ||
      potential_data_buffer_offset > m_entry_section_hdr->sh_size) {
    err_message = "Attempting to update at an entry point that is invalid.";
    m_dirty = false;
    return false;
  }

  m_dirty = true;

  uint64_t data_buffer_offset = m_entry_point - m_entry_section_hdr->sh_addr;
  uint8_t new_data_buffer[15] = {
      0,
  };
  size_t new_data_buffer_len{15};

  switch (m_extry_type) {
  case Extry::ExtryType::Stop: {
    ZydisEncoderRequest ret_encoder_request;
    ZyanStatus encoding_status = 0;
    memset(&ret_encoder_request, 0, sizeof(ret_encoder_request));

    ret_encoder_request.mnemonic = ZYDIS_MNEMONIC_RET;
    ret_encoder_request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;

    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(
            &ret_encoder_request, new_data_buffer, &new_data_buffer_len))) {
      err_message = std::string{"Failed to encode a ret instruction: "} +
                    std::to_string(encoding_status);
      m_dirty = false;
      return false;
    }
    break;
  }
  case Extry::ExtryType::Random: {
    // Seed with a real random value, if available
    std::random_device random_device;

    std::default_random_engine random_engine(random_device());
    std::uniform_int_distribution<int64_t> random_uniform_distribution(
        1, m_entry_section_hdr->sh_size);
    int64_t relative_jmp_target = random_uniform_distribution(random_engine);

    ZydisEncoderRequest random_jmp_encoder_request;
    ZyanStatus encoding_status;
    memset(&random_jmp_encoder_request, 0, sizeof(ZydisEncoderRequest));

    random_jmp_encoder_request.mnemonic = ZYDIS_MNEMONIC_JMP;
    random_jmp_encoder_request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    random_jmp_encoder_request.operand_count = 1;
    random_jmp_encoder_request.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    random_jmp_encoder_request.operands[0].imm.s = relative_jmp_target;

    if (ZYAN_FAILED((encoding_status = ZydisEncoderEncodeInstruction(
                         &random_jmp_encoder_request, new_data_buffer,
                         &new_data_buffer_len)))) {
      err_message = std::string{"Failed to encode a jmp instruction: "} +
                    std::to_string(encoding_status);
      m_dirty = false;
      return false;
    }

    if (m_debug) {
      std::cout << "Rewriting and jumping to 0x" << std::hex
                << (m_entry_point + relative_jmp_target + new_data_buffer_len)
                << std::dec << ".\n";
    }
    break;
  }
  case Extry::ExtryType::Infinite: {
    if (m_debug) {
      std::cout << "Rewriting and adding an infinite loop at " << std::hex
                << m_entry_point << std::dec << ".\n";
    }

    ZydisEncoderRequest infinite_loop_encoder_request;
    ZyanStatus encoding_status;
    memset(&infinite_loop_encoder_request, 0, sizeof(ZydisEncoderRequest));

    infinite_loop_encoder_request.mnemonic = ZYDIS_MNEMONIC_JMP;
    infinite_loop_encoder_request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    infinite_loop_encoder_request.operand_count = 1;
    infinite_loop_encoder_request.operands[0].type =
        ZYDIS_OPERAND_TYPE_IMMEDIATE;
    infinite_loop_encoder_request.operands[0].imm.s = -2;

    if (ZYAN_FAILED((encoding_status = ZydisEncoderEncodeInstruction(
                         &infinite_loop_encoder_request, new_data_buffer,
                         &new_data_buffer_len)))) {
      err_message = std::string{"Failed to encode a jmp instruction: "} +
                    std::to_string(encoding_status);
      m_dirty = false;
      return false;
    }
    break;
  }
  default:
    __builtin_unreachable();
  }

  // Copy new_data_buffer_len of new_data_buffer to (((uint8_t
  // *)m_entry_section_data->d_buf) + data_buffer_offset)
  uint8_t *replacement_instructions_target =
      (uint8_t *)(((uint8_t *)m_entry_section_data->d_buf) +
                  data_buffer_offset);
  memcpy(replacement_instructions_target, new_data_buffer, new_data_buffer_len);

  if (!elf_flagshdr(m_entry_section, ELF_C_SET, ELF_F_DIRTY) ||
      !elf_flagscn(m_entry_section, ELF_C_SET, ELF_F_DIRTY) ||
      !elf_flagdata(m_entry_section_data, ELF_C_SET, ELF_F_DIRTY) ||
      !elf_flagehdr(m_elf_handle, ELF_C_SET, ELF_F_DIRTY) ||
      !elf_flagelf(m_elf_handle, ELF_C_SET, ELF_F_DIRTY)) {
    err_message = "Failed to flag the updated ELF file as dirty.";
    m_dirty = false;
    return false;
  }
  return true;
}

bool Extry::save(std::string &err_message) {
  if (!m_dirty) {
    err_message = "Will not save an ELF file that is not dirty.\n";
    if (m_debug) {
      std::cout << "Attempt to save() an ELF that is not dirty.\n";
    }
    return false;
  }

  int elf_update_result{-1};
  if ((elf_update_result = elf_update(m_elf_handle, ELF_C_WRITE)) < 0) {
    err_message = std::string{elf_errmsg(-1)};
    return false;
  }
  if (m_debug) {
    std::cout << "Updated an ELF file with " << elf_update_result
              << " bytes.\n";
  }
  m_dirty = false;
  return true;
}
