#pragma once
#include <string>

class Logger {
public:
    static Logger& getInstance(); // instanță globală

    void logAction(const std::string& entity, const std::string& action);

private:
    Logger(); // constructor privat
    ~Logger() = default;

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void writeString(std::ofstream& out, const std::string& str);
    std::string filename;
};
