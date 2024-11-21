// EVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2020 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <evmc/tooling.hpp>
#include <chrono>
#include <ostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iostream>
#include <fstream>
#include <stdlib.h>

namespace evmc {
    std::string bytes_to_hex(const uint8_t* src, const size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (size_t i = 0; i < length; i++) {
            ss << std::hex << std::setw(2) << static_cast<int>(src[i]);
        }
        return ss.str();
    }

    std::string bytes_to_hex(const bytes& src) {
        // convert src to uint8_t array with size to call previous function
        return bytes_to_hex(src.data(), src.size());
    }

    void to_json(nlohmann::json& j, const bytes32& p) {
        j = bytes_to_hex(p.bytes, 32);
    }


    void to_json(nlohmann::json& j, const address& p) {
        j = bytes_to_hex(p.bytes, 20);
    }

    void to_json(nlohmann::json& j, const MockedHost::log_record& p) {
        j = nlohmann::json{ {"address", p.creator}, {"data", bytes_to_hex(p.data)}, {"topics", p.topics} };
    }
}

namespace nlohmann {
    template <typename T>
    struct adl_serializer<std::unordered_map<evmc::bytes32, T>> {
        static void to_json(json& j, const std::unordered_map<evmc::bytes32, T>& map) {
            for (const auto &[key, value] : map)
            {
                j[evmc::bytes_to_hex(key.bytes, 32)] = value;
            }
        }
    };

    template <typename T>
    struct adl_serializer<std::unordered_map<evmc::address, T>> {
        static void to_json(json& j, const std::unordered_map<evmc::address, T>& map) {
            for (const auto &[key, value] : map)
            {
                j[evmc::bytes_to_hex(key.bytes, 20)] = value;
            }
        }
    };
}

namespace evmc {
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(StorageValue, current, original);
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(MockedAccount, storage, transient_storage);
}


namespace evmc::tooling
{
namespace
{
/// The address where a new contract is created with --create option.
constexpr auto create_address = 0xc9ea7ed000000000000000000000000000000001_address;

/// The gas limit for contract creation.
constexpr auto create_gas = 10'000'000;

/// MAGIC bytes denoting an EOF container.
constexpr uint8_t MAGIC[] = {0xef, 0x00};

auto bench(MockedHost& host,
           evmc::VM& vm,
           evmc_revision rev,
           const evmc_message& msg,
           bytes_view code,
           const evmc::Result& expected_result,
           std::ostream& out)
{
    {
        using clock = std::chrono::steady_clock;
        using unit = std::chrono::nanoseconds;
        constexpr auto unit_name = " ns";
        constexpr auto target_bench_time = std::chrono::seconds{1};
        constexpr auto warning =
            "WARNING! Inconsistent execution result likely due to the use of storage ";

        // Probe run: execute once again the already warm code to estimate a single run time.
        const auto probe_start = clock::now();
        const auto result = vm.execute(host, rev, msg, code.data(), code.size());
        const auto bench_start = clock::now();
        const auto probe_time = bench_start - probe_start;

        if (result.gas_left != expected_result.gas_left)
            out << warning << "(gas used: " << (msg.gas - result.gas_left) << ")\n";
        if (bytes_view{result.output_data, result.output_size} !=
            bytes_view{expected_result.output_data, expected_result.output_size})
            out << warning << "(output: " << hex({result.output_data, result.output_size}) << ")\n";

        // Benchmark loop.
        const auto num_iterations = std::max(static_cast<int>(target_bench_time / probe_time), 1);
        for (int i = 0; i < num_iterations; ++i)
            vm.execute(host, rev, msg, code.data(), code.size());
        const auto bench_time = (clock::now() - bench_start) / num_iterations;

        out << "Time:     " << std::chrono::duration_cast<unit>(bench_time).count() << unit_name
            << " (avg of " << num_iterations << " iterations)\n";
    }
}

bool is_eof_container(bytes_view code)
{
    return code.size() >= 2 && code[0] == MAGIC[0] && code[1] == MAGIC[1];
}

void dump_storage(MockedHost& host) {
    const auto file_path = getenv("_STORAGE_DUMP_FILE");
    std::ofstream file(file_path);
    nlohmann::json j = host.accounts;
    file << j;
    file.flush();
    file.close();
}

void dump_logs(MockedHost& host) {
    const auto file_path = getenv("_LOGS_DUMP_FILE");
    std::ofstream file(file_path);
    nlohmann::json j = host.recorded_logs;
    file << j;
    file.flush();
    file.close();
}

}  // namespace

int run(VM& vm,
        evmc_revision rev,
        int64_t gas,
        bytes_view code,
        bytes_view input,
        bool create,
        bool bench,
        std::ostream& out)
{
    out << (create ? "Creating and executing on " : "Executing on ") << rev << " with " << gas
        << " gas limit\n";

    MockedHost host;

    evmc_message msg{};
    msg.gas = gas;
    msg.input_data = input.data();
    msg.input_size = input.size();

    bytes_view exec_code = code;
    if (create)
    {
        evmc_message create_msg{};
        create_msg.kind = is_eof_container(code) ? EVMC_EOFCREATE : EVMC_CREATE;
        create_msg.recipient = create_address;
        create_msg.gas = create_gas;

        const auto create_result = vm.execute(host, rev, create_msg, code.data(), code.size());
        if (create_result.status_code != EVMC_SUCCESS)
        {
            out << "Contract creation failed: " << create_result.status_code << "\n";
            return create_result.status_code;
        }

        auto& created_account = host.accounts[create_address];
        created_account.code = bytes(create_result.output_data, create_result.output_size);

        msg.recipient = create_address;
        exec_code = created_account.code;
    }
    out << "\n";

    const auto result = vm.execute(host, rev, msg, exec_code.data(), exec_code.size());

    tooling::dump_logs(host);
    tooling::dump_storage(host);

    if (bench)
        tooling::bench(host, vm, rev, msg, exec_code, result, out);

    const auto gas_used = msg.gas - result.gas_left;
    out << "Result:   " << result.status_code << "\nGas used: " << gas_used << "\n";

    if (result.status_code == EVMC_SUCCESS || result.status_code == EVMC_REVERT)
        out << "Output:   " << hex({result.output_data, result.output_size}) << "\n";

    return 0;
}
}  // namespace evmc::tooling
