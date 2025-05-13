#define _CRT_SECURE_NO_WARNINGS
#include "Logger.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>

Logger::Logger() {
    filename = "jurnal.bin"; // default location
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::writeString(std::ofstream& out, const std::string& str) {
    uint32_t len = str.size();
    out.write(reinterpret_cast<const char*>(&len), sizeof(len));
    out.write(str.c_str(), len);
}

void Logger::logAction(const std::string& entity, const std::string& action) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char date_buf[20], time_buf[20];
    std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", std::localtime(&now_time));
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&now_time));

    std::ofstream out(filename, std::ios::binary | std::ios::app);
    if (!out) {
        std::cerr << "Eroare la deschiderea fisierului de log\n";
        return;
    }

    writeString(out, date_buf);
    writeString(out, time_buf);
    writeString(out, entity);
    writeString(out, action);

    out.close();
}
