 #ifndef JSON_FORWARDS_H_INCLUDED
 # define JSON_FORWARDS_H_INCLUDED

 #if !defined(JSON_IS_AMALGAMATION)
 # include "banana/json/config.h"
 #endif // if !defined(JSON_IS_AMALGAMATION)

 namespace Json {
    
        // writer.h
        class FastWriter;
        class StyledWriter;
    
        // reader.h
        class Reader;
    
        // features.h
        class Features;
    
        // value.h
        typedef unsigned int ArrayIndex;
        class StaticString;
        class Path;
        class PathArgument;
        class Value;
        class ValueIteratorBase;
        class ValueIterator;
        class ValueConstIterator;
     #ifdef JSON_VALUE_USE_INTERNAL_MAP
        class ValueMapAllocator;
        class ValueInternalLink;
        class ValueInternalArray;
        class ValueInternalMap;
     #endif // #ifdef JSON_VALUE_USE_INTERNAL_MAP
    
     } // namespace Json


 #endif // JSON_FORWARDS_H_INCLUDED
