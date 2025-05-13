#ifndef IDGENERATOR_H
#define IDGENERATOR_H

#include <random>

namespace IDGenerator {

    static int generate() {
        static std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(1, 1'000);
        return dist(rng);
    }

}

#endif // IDGENERATOR_H