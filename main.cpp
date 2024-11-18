#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <windows.h>
#include <openssl/sha.h>

// 判断路径是否是文件夹
bool IsDirectory(const std::string &path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

// 判断路径是否是文件
bool IsFile(const std::string &path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES &&
            !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

// 计算文件的 SHA256 哈希值
std::string CalculateFileHash(const std::string &file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    // 检查文件是否为空
    if (file.peek() == std::ifstream::traits_type::eof()) {
        return "EMPTY_FILE";
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

// 递归遍历目录中的文件
void ProcessDirectory(const std::string &dir_path) {
    std::string search_path = dir_path + "\\*";
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);

    if (hFind == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to open directory: " + dir_path);
    }

    std::vector<std::string> entries;

    // 收集目录中的所有条目
    do {
        std::string entry_name = find_data.cFileName;

        // 跳过 "." 和 ".."
        if (entry_name != "." && entry_name != "..") {
            std::string full_path = dir_path;

            // 确保路径末尾只有一个斜杠
            if (full_path.back() != '\\' && full_path.back() != '/') {
                full_path += '/';
            }
            full_path += entry_name;

            // 将路径格式统一为 "/"
            std::replace(full_path.begin(), full_path.end(), '\\', '/');

            entries.push_back(full_path);
        }
    } while (FindNextFileA(hFind, &find_data) != 0);

    FindClose(hFind);

    // 对条目按文件名排序
    std::sort(entries.begin(), entries.end());

    // 递归处理排序后的条目
    for (const auto &entry: entries) {
        if (IsDirectory(entry)) {
            ProcessDirectory(entry);
        } else if (IsFile(entry)) {
            try {
                std::string hash = CalculateFileHash(entry);
                // 增大对齐宽度
                std::cout << std::left << std::setw(50) << entry << ": " << hash << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "Error processing file " << entry << ": " << e.what() << std::endl;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <directory>" << std::endl;
        return 1;
    }

    std::string input_path = argv[1];

    if (IsDirectory(input_path)) {
        try {
            ProcessDirectory(input_path);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    } else if (IsFile(input_path)) {
        try {
            std::string hash = CalculateFileHash(input_path);
            std::cout << std::left << std::setw(40) << input_path << ": " << hash << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    } else {
        std::cerr << input_path << " is neither a file nor a directory." << std::endl;
        return 1;
    }

    return 0;
}
