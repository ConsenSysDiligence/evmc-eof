// EVMC: Ethereum Client-VM Connector API.
// Copyright 2019 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <CLI/CLI.hpp>
#include <evmc/hex.hpp>
#include <evmc/loader.h>
#include <evmc/tooling.hpp>
#include <fstream>
#include <stdlib.h>

namespace
{
/// If the argument starts with @ returns the hex-decoded contents of the file
/// at the path following the @. Otherwise, returns the argument.
/// @todo The file content is expected to be a hex string but not validated.
evmc::bytes load_from_hex(const std::string& str)
{
    if (str[0] == '@')  // The argument is file path.
    {
        const auto path = str.substr(1);
        std::ifstream file{path};
        auto out = evmc::from_spaced_hex(std::istreambuf_iterator<char>{file},
                                         std::istreambuf_iterator<char>{});
        if (!out)
            throw std::invalid_argument{"invalid hex in " + path};
        return out.value();
    }

    return evmc::from_hex(str).value();  // Should be validated already.
}

struct HexOrFileValidator : public CLI::Validator
{
    HexOrFileValidator() : CLI::Validator{"HEX|@FILE"}
    {
        func_ = [](const std::string& str) -> std::string {
            if (!str.empty() && str[0] == '@')
                return CLI::ExistingFile(str.substr(1));
            if (!evmc::validate_hex(str))
                return "invalid hex";
            return {};
        };
    }
};
}  // namespace

int main(int argc, const char** argv) noexcept
{
    using namespace evmc;

    try
    {
        const HexOrFileValidator HexOrFile;

        std::string vm_config;
        std::string code_arg;
        int64_t gas = 1000000;
        auto rev = EVMC_LATEST_STABLE_REVISION;
        std::string input_arg;
        auto create = false;
        auto bench = false;
        std::string storage_dump_file = "storage_dump.json";
        std::string logs_dump_file = "logs_dump.json";

        CLI::App app{"EVMC tool"};
        const auto& version_flag = *app.add_flag("--version", "Print version information and exit");
        const auto& vm_option =
            *app.add_option("--vm", vm_config, "EVMC VM module")->envname("EVMC_VM");

        auto& run_cmd = *app.add_subcommand("run", "Execute EVM bytecode")->fallthrough();
        run_cmd.add_option("code", code_arg, "Bytecode")->required()->check(HexOrFile);
        run_cmd.add_option("--gas", gas, "Execution gas limit")
            ->capture_default_str()
            ->check(CLI::Range(0, 1000000000));
        run_cmd.add_option("--rev", rev, "EVM revision")->capture_default_str();
        run_cmd.add_option("--input", input_arg, "Input bytes")->check(HexOrFile);
        run_cmd.add_flag(
            "--create", create,
            "Create new contract out of the code and then execute this contract with the input");
        run_cmd.add_flag(
            "--bench", bench,
            "Benchmark execution time (state modification may result in unexpected behaviour)");
        run_cmd.add_option("--storage-dump-file", storage_dump_file, "file path to dump contract's storage")->capture_default_str();
        run_cmd.add_option("--logs-dump-file", logs_dump_file, "file path to dump contract's logs")->capture_default_str();

        try
        {
            app.parse(argc, argv);
            evmc::VM vm;
            if (vm_option.count() != 0)
            {
                evmc_loader_error_code ec = EVMC_LOADER_UNSPECIFIED_ERROR;
                vm = VM{evmc_load_and_configure(vm_config.c_str(), &ec)};
                if (ec != EVMC_LOADER_SUCCESS)
                {
                    const auto error = evmc_last_error_msg();
                    if (error != nullptr)
                        std::cerr << error << "\n";
                    else
                        std::cerr << "Loading error " << ec << "\n";
                    return static_cast<int>(ec);
                }
            }

            // Handle the --version flag first and exit when present.
            if (version_flag)
            {
                if (vm)
                    std::cout << vm.name() << " " << vm.version() << " (" << vm_config << ")\n";

                std::cout << "EVMC " PROJECT_VERSION;
                if (argc >= 1)
                    std::cout << " (" << argv[0] << ")";
                std::cout << "\n";
                return 0;
            }

            if (run_cmd)
            {
                // For run command the --vm is required.
                if (vm_option.count() == 0)
                    throw CLI::RequiredError{vm_option.get_name()};

                std::cout << "Config: " << vm_config << "\n";

                // If code_arg or input_arg contains invalid hex string an exception is thrown.
                const auto code = load_from_hex(code_arg);
                const auto input = load_from_hex(input_arg);

                setenv("_STORAGE_DUMP_FILE", storage_dump_file.c_str(), 1);
                setenv("_LOGS_DUMP_FILE", logs_dump_file.c_str(), 1);

                return tooling::run(vm, rev, gas, code, input, create, bench, std::cout);
            }

            return 0;
        }
        catch (const CLI::ParseError& e)
        {
            return app.exit(e);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return -1;
    }
    catch (...)
    {
        return -2;
    }
}
