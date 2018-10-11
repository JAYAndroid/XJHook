#ifndef CPPTL_JSON_H_INCLUDED
# define CPPTL_JSON_H_INCLUDED

#if !defined(JSON_IS_AMALGAMATION)

# include "banana/json/forwards.h"

#endif // if !defined(JSON_IS_AMALGAMATION)

# include <string>
# include <vector>

# ifndef JSON_USE_CPPTL_SMALLMAP

#  include <map>

# else
#  include <cpptl/smallmap.h>
# endif
# ifdef JSON_USE_CPPTL
#  include <cpptl/forwards.h>
# endif

namespace Json {

    enum ValueType {
        nullValue = 0,
        intValue,
        uintValue,
        realValue,
        stringValue,
        booleanValue,
        arrayValue,
        objectValue
    };

    enum CommentPlacement {
        commentBefore = 0,
        commentAfterOnSameLine,
        commentAfter,
        numberOfCommentPlacement
    };

    //# ifdef JSON_USE_CPPTL
    //   typedef CppTL::AnyEnumerator<const char *> EnumMemberNames;
    //   typedef CppTL::AnyEnumerator<const Value &> EnumValues;
    //# endif

    class JSON_API StaticString {
    public:
        explicit StaticString(const char *czstring)
                : str_(czstring) {
        }

        operator const char *() const {
            return str_;
        }

        const char *c_str() const {
            return str_;
        }

    private:
        const char *str_;
    };

    class JSON_API Value {
        friend class ValueIteratorBase;

# ifdef JSON_VALUE_USE_INTERNAL_MAP
        friend class ValueInternalLink;
        friend class ValueInternalMap;
# endif
    public:
        typedef std::vector<std::string> Members;
        typedef ValueIterator iterator;
        typedef ValueConstIterator const_iterator;
        typedef Json::UInt UInt;
        typedef Json::Int Int;
# if defined(JSON_HAS_INT64)
        typedef Json::UInt64 UInt64;
        typedef Json::Int64 Int64;
#endif // defined(JSON_HAS_INT64)
        typedef Json::LargestInt LargestInt;
        typedef Json::LargestUInt LargestUInt;
        typedef Json::ArrayIndex ArrayIndex;

        static const Value null;
        static const LargestInt minLargestInt;
        static const LargestInt maxLargestInt;
        static const LargestUInt maxLargestUInt;

        static const Int minInt;
        static const Int maxInt;
        static const UInt maxUInt;

        static const Int64 minInt64;
        static const Int64 maxInt64;
        static const UInt64 maxUInt64;

    private:
#ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION
# ifndef JSON_VALUE_USE_INTERNAL_MAP

        class CZString {
        public:
            enum DuplicationPolicy {
                noDuplication = 0,
                duplicate,
                duplicateOnCopy
            };

            CZString(ArrayIndex index);

            CZString(const char *cstr, DuplicationPolicy allocate);

            CZString(const CZString &other);

            ~CZString();

            CZString &operator=(const CZString &other);

            bool operator<(const CZString &other) const;

            bool operator==(const CZString &other) const;

            ArrayIndex index() const;

            const char *c_str() const;

            bool isStaticString() const;

        private:
            void swap(CZString &other);

            const char *cstr_;
            ArrayIndex index_;
        };

    public:
#  ifndef JSON_USE_CPPTL_SMALLMAP
        typedef std::map<CZString, Value> ObjectValues;
#  else
        typedef CppTL::SmallMap<CZString, Value> ObjectValues;
#  endif // ifndef JSON_USE_CPPTL_SMALLMAP
# endif // ifndef JSON_VALUE_USE_INTERNAL_MAP
#endif // ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION

    public:
        Value(ValueType type = nullValue);

        Value(Int value);

        Value(UInt value);

#if defined(JSON_HAS_INT64)

        Value(Int64 value);

        Value(UInt64 value);

#endif // if defined(JSON_HAS_INT64)

        Value(double value);

        Value(const char *value);

        Value(const char *beginValue, const char *endValue);

        Value(const StaticString &value);

        Value(const std::string &value);

# ifdef JSON_USE_CPPTL
        Value( const CppTL::ConstString &value );
# endif

        Value(bool value);

        Value(const Value &other);

        ~Value();

        Value &operator=(const Value &other);

        void swap(Value &other);

        ValueType type() const;

        bool operator<(const Value &other) const;

        bool operator<=(const Value &other) const;

        bool operator>=(const Value &other) const;

        bool operator>(const Value &other) const;

        bool operator==(const Value &other) const;

        bool operator!=(const Value &other) const;

        int compare(const Value &other) const;

        const char *asCString() const;

        std::string asString() const;

# ifdef JSON_USE_CPPTL
        CppTL::ConstString asConstString() const;
# endif

        Int asInt() const;

        UInt asUInt() const;

        Int64 asInt64() const;

        UInt64 asUInt64() const;

        LargestInt asLargestInt() const;

        LargestUInt asLargestUInt() const;

        float asFloat() const;

        double asDouble() const;

        bool asBool() const;

        bool isNull() const;

        bool isBool() const;

        bool isInt() const;

        bool isUInt() const;

        bool isIntegral() const;

        bool isDouble() const;

        bool isNumeric() const;

        bool isString() const;

        bool isArray() const;

        bool isObject() const;

        bool isConvertibleTo(ValueType other) const;

        ArrayIndex size() const;

        bool empty() const;

        bool operator!() const;

        void clear();

        void resize(ArrayIndex size);

        Value &operator[](ArrayIndex index);

        Value &operator[](int index);

        const Value &operator[](ArrayIndex index) const;

        const Value &operator[](int index) const;

        Value get(ArrayIndex index,
                  const Value &defaultValue) const;

        bool isValidIndex(ArrayIndex index) const;

        Value &append(const Value &value);

        Value &operator[](const char *key);

        const Value &operator[](const char *key) const;

        Value &operator[](const std::string &key);

        const Value &operator[](const std::string &key) const;

        Value &operator[](const StaticString &key);

# ifdef JSON_USE_CPPTL
        Value &operator[]( const CppTL::ConstString &key );
        const Value &operator[]( const CppTL::ConstString &key ) const;
# endif

        Value get(const char *key,
                  const Value &defaultValue) const;

        Value get(const std::string &key,
                  const Value &defaultValue) const;

# ifdef JSON_USE_CPPTL
        Value get( const CppTL::ConstString &key,
                   const Value &defaultValue ) const;
# endif

        Value removeMember(const char *key);

        Value removeMember(const std::string &key);

        bool isMember(const char *key) const;

        bool isMember(const std::string &key) const;

# ifdef JSON_USE_CPPTL
        bool isMember( const CppTL::ConstString &key ) const;
# endif

        Members getMemberNames() const;

        //# ifdef JSON_USE_CPPTL
        //      EnumMemberNames enumMemberNames() const;
        //      EnumValues enumValues() const;
        //# endif

        void setComment(const char *comment,
                        CommentPlacement placement);

        void setComment(const std::string &comment,
                        CommentPlacement placement);

        bool hasComment(CommentPlacement placement) const;

        std::string getComment(CommentPlacement placement) const;

        std::string toStyledString() const;

        const_iterator begin() const;

        const_iterator end() const;

        iterator begin();

        iterator end();

    private:
        Value &resolveReference(const char *key,
                                bool isStatic);

# ifdef JSON_VALUE_USE_INTERNAL_MAP
        inline bool isItemAvailable() const
        {
           return itemIsUsed_ == 0;
        }

        inline void setItemUsed( bool isUsed = true )
        {
           itemIsUsed_ = isUsed ? 1 : 0;
        }

        inline bool isMemberNameStatic() const
        {
           return memberNameIsStatic_ == 0;
        }

        inline void setMemberNameIsStatic( bool isStatic )
        {
           memberNameIsStatic_ = isStatic ? 1 : 0;
        }
# endif // # ifdef JSON_VALUE_USE_INTERNAL_MAP

    private:
        struct CommentInfo {
            CommentInfo();

            ~CommentInfo();

            void setComment(const char *text);

            char *comment_;
        };

        //struct MemberNamesTransform
        //{
        //   typedef const char *result_type;
        //   const char *operator()( const CZString &name ) const
        //   {
        //      return name.c_str();
        //   }
        //};

        union ValueHolder {
            LargestInt int_;
            LargestUInt uint_;
            double real_;
            bool bool_;
            char *string_;
# ifdef JSON_VALUE_USE_INTERNAL_MAP
            ValueInternalArray *array_;
            ValueInternalMap *map_;
#else
            ObjectValues *map_;
# endif
        } value_;
        ValueType type_ : 8;
        int allocated_ : 1;     // Notes: if declared as bool, bitfield is useless.
# ifdef JSON_VALUE_USE_INTERNAL_MAP
        unsigned int itemIsUsed_ : 1;      // used by the ValueInternalMap container.
        int memberNameIsStatic_ : 1;       // used by the ValueInternalMap container.
# endif
        CommentInfo *comments_;
    };


    class PathArgument {
    public:
        friend class Path;

        PathArgument();

        PathArgument(ArrayIndex index);

        PathArgument(const char *key);

        PathArgument(const std::string &key);

    private:
        enum Kind {
            kindNone = 0,
            kindIndex,
            kindKey
        };
        std::string key_;
        ArrayIndex index_;
        Kind kind_;
    };

    class Path {
    public:
        Path(const std::string &path,
             const PathArgument &a1 = PathArgument(),
             const PathArgument &a2 = PathArgument(),
             const PathArgument &a3 = PathArgument(),
             const PathArgument &a4 = PathArgument(),
             const PathArgument &a5 = PathArgument());

        const Value &resolve(const Value &root) const;

        Value resolve(const Value &root,
                      const Value &defaultValue) const;

        Value &make(Value &root) const;

    private:
        typedef std::vector<const PathArgument *> InArgs;
        typedef std::vector<PathArgument> Args;

        void makePath(const std::string &path,
                      const InArgs &in);

        void addPathInArg(const std::string &path,
                          const InArgs &in,
                          InArgs::const_iterator &itInArg,
                          PathArgument::Kind kind);

        void invalidPath(const std::string &path,
                         int location);

        Args args_;
    };


#ifdef JSON_VALUE_USE_INTERNAL_MAP

    class JSON_API ValueMapAllocator
    {
    public:
       virtual ~ValueMapAllocator();
       virtual ValueInternalMap *newMap() = 0;
       virtual ValueInternalMap *newMapCopy( const ValueInternalMap &other ) = 0;
       virtual void destructMap( ValueInternalMap *map ) = 0;
       virtual ValueInternalLink *allocateMapBuckets( unsigned int size ) = 0;
       virtual void releaseMapBuckets( ValueInternalLink *links ) = 0;
       virtual ValueInternalLink *allocateMapLink() = 0;
       virtual void releaseMapLink( ValueInternalLink *link ) = 0;
    };

    class JSON_API ValueInternalLink
    {
    public:
       enum { itemPerLink = 6 };  // sizeof(ValueInternalLink) = 128 on 32 bits architecture.
       enum InternalFlags {
              flagAvailable = 0,
              flagUsed = 1
           };

       ValueInternalLink();

       ~ValueInternalLink();

       Value items_[itemPerLink];
       char *keys_[itemPerLink];
       ValueInternalLink *previous_;
       ValueInternalLink *next_;
    };


    class JSON_API ValueInternalMap
    {
       friend class ValueIteratorBase;
       friend class Value;
    public:
       typedef unsigned int HashKey;
       typedef unsigned int BucketIndex;

# ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION
       struct IteratorState
       {
          IteratorState()
             : map_(0)
             , link_(0)
             , itemIndex_(0)
             , bucketIndex_(0)
          {
          }
          ValueInternalMap *map_;
          ValueInternalLink *link_;
          BucketIndex itemIndex_;
          BucketIndex bucketIndex_;
       };
# endif // ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION

       ValueInternalMap();
       ValueInternalMap( const ValueInternalMap &other );
       ValueInternalMap &operator =( const ValueInternalMap &other );
       ~ValueInternalMap();

       void swap( ValueInternalMap &other );

       BucketIndex size() const;

       void clear();

       bool reserveDelta( BucketIndex growth );

       bool reserve( BucketIndex newItemCount );

       const Value *find( const char *key ) const;

       Value *find( const char *key );

       Value &resolveReference( const char *key,
                                bool isStatic );

       void remove( const char *key );

       void doActualRemove( ValueInternalLink *link,
                            BucketIndex index,
                            BucketIndex bucketIndex );

       ValueInternalLink *&getLastLinkInBucket( BucketIndex bucketIndex );

       Value &setNewItem( const char *key,
                          bool isStatic,
                          ValueInternalLink *link,
                          BucketIndex index );

       Value &unsafeAdd( const char *key,
                         bool isStatic,
                         HashKey hashedKey );

       HashKey hash( const char *key ) const;

       int compare( const ValueInternalMap &other ) const;

    private:
       void makeBeginIterator( IteratorState &it ) const;
       void makeEndIterator( IteratorState &it ) const;
       static bool equals( const IteratorState &x, const IteratorState &other );
       static void increment( IteratorState &iterator );
       static void incrementBucket( IteratorState &iterator );
       static void decrement( IteratorState &iterator );
       static const char *key( const IteratorState &iterator );
       static const char *key( const IteratorState &iterator, bool &isStatic );
       static Value &value( const IteratorState &iterator );
       static int distance( const IteratorState &x, const IteratorState &y );

    private:
       ValueInternalLink *buckets_;
       ValueInternalLink *tailLink_;
       BucketIndex bucketsSize_;
       BucketIndex itemCount_;
    };

    class JSON_API ValueInternalArray
    {
       friend class Value;
       friend class ValueIteratorBase;
    public:
       enum { itemsPerPage = 8 };    // should be a power of 2 for fast divide and modulo.
       typedef Value::ArrayIndex ArrayIndex;
       typedef unsigned int PageIndex;

# ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION
       struct IteratorState // Must be a POD
       {
          IteratorState()
             : array_(0)
             , currentPageIndex_(0)
             , currentItemIndex_(0)
          {
          }
          ValueInternalArray *array_;
          Value **currentPageIndex_;
          unsigned int currentItemIndex_;
       };
# endif // ifndef JSONCPP_DOC_EXCLUDE_IMPLEMENTATION

       ValueInternalArray();
       ValueInternalArray( const ValueInternalArray &other );
       ValueInternalArray &operator =( const ValueInternalArray &other );
       ~ValueInternalArray();
       void swap( ValueInternalArray &other );

       void clear();
       void resize( ArrayIndex newSize );

       Value &resolveReference( ArrayIndex index );

       Value *find( ArrayIndex index ) const;

       ArrayIndex size() const;

       int compare( const ValueInternalArray &other ) const;

    private:
       static bool equals( const IteratorState &x, const IteratorState &other );
       static void increment( IteratorState &iterator );
       static void decrement( IteratorState &iterator );
       static Value &dereference( const IteratorState &iterator );
       static Value &unsafeDereference( const IteratorState &iterator );
       static int distance( const IteratorState &x, const IteratorState &y );
       static ArrayIndex indexOf( const IteratorState &iterator );
       void makeBeginIterator( IteratorState &it ) const;
       void makeEndIterator( IteratorState &it ) const;
       void makeIterator( IteratorState &it, ArrayIndex index ) const;

       void makeIndexValid( ArrayIndex index );

       Value **pages_;
       ArrayIndex size_;
       PageIndex pageCount_;
    };

    class JSON_API ValueArrayAllocator
    {
    public:
       virtual ~ValueArrayAllocator();
       virtual ValueInternalArray *newArray() = 0;
       virtual ValueInternalArray *newArrayCopy( const ValueInternalArray &other ) = 0;
       virtual void destructArray( ValueInternalArray *array ) = 0;
       virtual void reallocateArrayPageIndex( Value **&indexes,
                                              ValueInternalArray::PageIndex &indexCount,
                                              ValueInternalArray::PageIndex minNewIndexCount ) = 0;
       virtual void releaseArrayPageIndex( Value **indexes,
                                           ValueInternalArray::PageIndex indexCount ) = 0;
       virtual Value *allocateArrayPage() = 0;
       virtual void releaseArrayPage( Value *value ) = 0;
    };
#endif // #ifdef JSON_VALUE_USE_INTERNAL_MAP


    class ValueIteratorBase {
    public:
        typedef unsigned int size_t;
        typedef int difference_type;
        typedef ValueIteratorBase SelfType;

        ValueIteratorBase();

#ifndef JSON_VALUE_USE_INTERNAL_MAP

        explicit ValueIteratorBase(const Value::ObjectValues::iterator &current);

#else
        ValueIteratorBase( const ValueInternalArray::IteratorState &state );
        ValueIteratorBase( const ValueInternalMap::IteratorState &state );
#endif

        bool operator==(const SelfType &other) const {
            return isEqual(other);
        }

        bool operator!=(const SelfType &other) const {
            return !isEqual(other);
        }

        difference_type operator-(const SelfType &other) const {
            return computeDistance(other);
        }

        Value key() const;

        UInt index() const;

        const char *memberName() const;

    protected:
        Value &deref() const;

        void increment();

        void decrement();

        difference_type computeDistance(const SelfType &other) const;

        bool isEqual(const SelfType &other) const;

        void copy(const SelfType &other);

    private:
#ifndef JSON_VALUE_USE_INTERNAL_MAP
        Value::ObjectValues::iterator current_;
        // Indicates that iterator is for a null value.
        bool isNull_;
#else
        union
        {
           ValueInternalArray::IteratorState array_;
           ValueInternalMap::IteratorState map_;
        } iterator_;
        bool isArray_;
#endif
    };

    class ValueConstIterator : public ValueIteratorBase {
        friend class Value;

    public:
        typedef unsigned int size_t;
        typedef int difference_type;
        typedef const Value &reference;
        typedef const Value *pointer;
        typedef ValueConstIterator SelfType;

        ValueConstIterator();

    private:
#ifndef JSON_VALUE_USE_INTERNAL_MAP

        explicit ValueConstIterator(const Value::ObjectValues::iterator &current);

#else
        ValueConstIterator( const ValueInternalArray::IteratorState &state );
        ValueConstIterator( const ValueInternalMap::IteratorState &state );
#endif
    public:
        SelfType &operator=(const ValueIteratorBase &other);

        SelfType operator++(int) {
            SelfType temp(*this);
            ++*this;
            return temp;
        }

        SelfType operator--(int) {
            SelfType temp(*this);
            --*this;
            return temp;
        }

        SelfType &operator--() {
            decrement();
            return *this;
        }

        SelfType &operator++() {
            increment();
            return *this;
        }

        reference operator*() const {
            return deref();
        }
    };


    class ValueIterator : public ValueIteratorBase {
        friend class Value;

    public:
        typedef unsigned int size_t;
        typedef int difference_type;
        typedef Value &reference;
        typedef Value *pointer;
        typedef ValueIterator SelfType;

        ValueIterator();

        ValueIterator(const ValueConstIterator &other);

        ValueIterator(const ValueIterator &other);

    private:
#ifndef JSON_VALUE_USE_INTERNAL_MAP

        explicit ValueIterator(const Value::ObjectValues::iterator &current);

#else
        ValueIterator( const ValueInternalArray::IteratorState &state );
        ValueIterator( const ValueInternalMap::IteratorState &state );
#endif
    public:

        SelfType &operator=(const SelfType &other);

        SelfType operator++(int) {
            SelfType temp(*this);
            ++*this;
            return temp;
        }

        SelfType operator--(int) {
            SelfType temp(*this);
            --*this;
            return temp;
        }

        SelfType &operator--() {
            decrement();
            return *this;
        }

        SelfType &operator++() {
            increment();
            return *this;
        }

        reference operator*() const {
            return deref();
        }
    };


} // namespace Json


#endif // CPPTL_JSON_H_INCLUDED
