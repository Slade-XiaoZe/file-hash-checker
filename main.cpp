#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <openssl/sha.h>

// 判断路径是否是文件夹
bool IsDirectory(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false; // 无法访问该路径
    }
    return (info.st_mode & S_IFDIR) != 0; // 是否为目录
}

// 判断路径是否是文件
bool IsFile(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false; // 无法访问该路径
    }
    return (info.st_mode & S_IFREG) != 0; // 是否为普通文件
}

// 计算文件的 SHA256 哈希值
std::string CalculateFileHash(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path);
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << R"(Usage: .\file_hash_checker.exe <file_or_dir>)" << std::endl;
        return 1;
    }

    std::string input_path = argv[1];

    if (IsDirectory(input_path)) {
        std::cout << input_path << " is a directory." << std::endl;
        // 在此处可以添加目录处理逻辑
    } else if (IsFile(input_path)) {
        try {
            std::string hash = CalculateFileHash(input_path);
            std::cout << "SHA256 Hash of file " << input_path << ": " << hash << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    } else {
        std::cerr << input_path << " is neither a file nor a directory." << std::endl;
    }

    return 0;
}
