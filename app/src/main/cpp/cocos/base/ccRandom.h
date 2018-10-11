#ifndef __ccRandom_H_
#define __ccRandom_H_

#include <random>
#include <cstdlib>

#include "../platform/CCPlatformMacros.h"

/**
* @addtogroup base
* @{
*/
NS_CC_BEGIN


/**
 * @class RandomHelper
 * @brief A helper class for creating random number.
 */
class CC_DLL RandomHelper {
        public:
        template<typename T>
        static T random_real(T min, T max) {
            std::uniform_real_distribution<T> dist(min, max);
            auto &mt = RandomHelper::getEngine();
            return dist(mt);
        }

        template<typename T>
        static T random_int(T min, T max) {
            std::uniform_int_distribution<T> dist(min, max);
            auto &mt = RandomHelper::getEngine();
            return dist(mt);
        }
        private:
        static std::mt19937 &getEngine();
};

/**
 * Returns a random value between `min` and `max`.
 */
template<typename T>
inline T random(T min, T max) {
    return RandomHelper::random_int<T>(min, max);
}

template<>
inline float random(float min, float max) {
    return RandomHelper::random_real(min, max);
}

template<>
inline long double random(long double min, long double max) {
    return RandomHelper::random_real(min, max);
}

template<>
inline double random(double min, double max) {
    return RandomHelper::random_real(min, max);
}

/**
 * Returns a random int between 0 and RAND_MAX.
 */
inline int random() {
    return cocos2d::random(0, RAND_MAX);
};

/**
 * Returns a random float between -1 and 1.
 * It can be seeded using std::srand(seed);
 */
inline float rand_minus1_1() {
    // FIXME: using the new c++11 random engine generator
    // without a proper way to set a seed is not useful.
    // Resorting to the old random method since it can
    // be seeded using std::srand()
    return ((std::rand() / (float)RAND_MAX) * 2) -1;

//    return cocos2d::random(-1.f, 1.f);
};

/**
 * Returns a random float between 0 and 1.
 * It can be seeded using std::srand(seed);
 */
inline float rand_0_1() {
    // FIXME: using the new c++11 random engine generator
    // without a proper way to set a seed is not useful.
    // Resorting to the old random method since it can
    // be seeded using std::srand()
    return std::rand() / (float)RAND_MAX;

//    return cocos2d::random(0.f, 1.f);
};


NS_CC_END
// end group
/// @}
#endif //__ccRandom_H_