#ifndef STRING_UTILS_H
#define STRING_UTILS_H

#include <iostream>
#include <sstream>
#include <thread>

static std::string getThreadIdString() {
    std::stringstream ss;
    ss << std::this_thread::get_id();
    return ss.str();
}

#endif // STRING_UTILS_H