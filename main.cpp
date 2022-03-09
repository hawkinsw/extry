#include <args.hxx>
#include <cstdlib>
#include <extry/extry.hpp>
#include <filesystem>
#include <iostream>
#include <system_error>

bool file_exists(const std::string &filename) {
  std::filesystem::path filename_path{filename};
  return std::filesystem::is_regular_file(filename_path);
}

bool containing_path_exists(const std::string &filename) {
  std::filesystem::path filename_path{filename};
  return std::filesystem::is_directory(filename_path.parent_path());
}

bool copy_elf_files(const std::string &source, const std::string &destination,
                    std::string &copy_err_msg) {
  auto source_path{std::filesystem::path{source}};
  auto destination_path{std::filesystem::path{destination}};
  std::error_code copy_err;

  std::filesystem::copy(source_path, destination_path,
                        std::filesystem::copy_options::overwrite_existing,
                        copy_err);

  if (copy_err) {
    copy_err_msg = copy_err.message();
  }

  return !copy_err;
}

int main(int argc, char *argv[]) {
  args::ArgumentParser parser("Hijack the entry point of an ELF file.");
  args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
  args::Flag debug(parser, "debug", "Enable debugging.", {"d", "debug"});

  args::Group extry_type_group(parser,
                               "Extry type:", args::Group::Validators::Xor);
  args::Flag foo(extry_type_group, "random", "Random", {'r'});
  args::Flag bar(extry_type_group, "stop", "Stop", {'s'});
  args::Flag baz(extry_type_group, "infinite", "Infinite", {'i'});

  args::Positional<std::string> input_elf_name(
      parser, "input", "The path to the ELF file whose entry point to hijack.",
      args::Options::Required);
  args::Positional<std::string> output_elf_name(
      parser, "output",
      "The path to the location to store the rewritten binary.",
      args::Options::Required);

  try {
    parser.ParseCLI(argc, argv);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  } catch (args::ValidationError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }

  if (!file_exists(input_elf_name.Get())) {
    std::cerr << "Input file (" << input_elf_name.Get()
              << ") does not exist.\n";
    exit(EXIT_FAILURE);
  }

  if (!containing_path_exists(output_elf_name.Get())) {
    std::cerr << "Directory containing output file (" << output_elf_name.Get()
              << ") does not exist.\n";
    exit(EXIT_FAILURE);
  }

  /*
   * First, let's copy the input to the output -- then we'll modify the output
   * file!
   */

  std::string copy_err_msg;
  if (!copy_elf_files(input_elf_name.Get(), output_elf_name.Get(),
                      copy_err_msg)) {
    std::cerr << "Could not create the output file named "
              << output_elf_name.Get() << ": " << copy_err_msg << "\n";
    exit(EXIT_FAILURE);
  }

  Extry extry{Extry::ExtryType::Stop, true};

  std::string extry_err{""};
  if (!extry.load(output_elf_name.Get(), extry_err)) {
    std::cerr << "An error occurred initializing from file "
              << output_elf_name.Get() << ": " << extry_err << "\n";
    exit(EXIT_FAILURE);
  }

  if (!extry.rewrite(extry_err)) {
    std::cerr << "An error occurred initializing from file "
              << output_elf_name.Get() << ": " << extry_err << "\n";
    exit(EXIT_FAILURE);
  }

  if (!extry.save(extry_err)) {
    std::cerr << "An error occurred initializing from file "
              << output_elf_name.Get() << ": " << extry_err << "\n";
    exit(EXIT_FAILURE);
  }
  return 0;
}