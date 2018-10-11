#ifndef CPPTL_JSON_READER_H_INCLUDED
# define CPPTL_JSON_READER_H_INCLUDED

#if !defined(JSON_IS_AMALGAMATION)

# include "features.h"
# include "value.h"

#endif // if !defined(JSON_IS_AMALGAMATION)

# include <deque>
# include <stack>
# include <string>
//# include <iostream>

namespace Json {

    class JSON_API Reader {
    public:
        typedef char Char;
        typedef const Char *Location;

        Reader();

        Reader(const Features &features);

        bool parse(const std::string &document,
                   Value &root,
                   bool collectComments = true);

        bool parse(const char *beginDoc, const char *endDoc,
                   Value &root,
                   bool collectComments = true);

        bool parse(std::istream &is,
                   Value &root,
                   bool collectComments = true);

        JSONCPP_DEPRECATED("Use getFormattedErrorMessages instead")

        std::string getFormatedErrorMessages() const;

        std::string getFormattedErrorMessages() const;

    private:
        enum TokenType {
            tokenEndOfStream,
            tokenObjectBegin,
            tokenObjectEnd,
            tokenArrayBegin,
            tokenArrayEnd,
            tokenString,
            tokenNumber,
            tokenTrue,
            tokenFalse,
            tokenNull,
            tokenArraySeparator,
            tokenMemberSeparator,
            tokenComment,
            tokenError
        };

        class Token {
        public:
            TokenType type_;
            Location start_;
            Location end_;
        };

        class ErrorInfo {
        public:
            Token token_;
            std::string message_;
            Location extra_;
        };

        typedef std::deque<ErrorInfo> Errors;

        bool expectToken(TokenType type, Token &token, const char *message);

        bool readToken(Token &token);

        void skipSpaces();

        bool match(Location pattern,
                   int patternLength);

        bool readComment();

        bool readCStyleComment();

        bool readCppStyleComment();

        bool readString();

        void readNumber();

        bool readValue();

        bool readObject(Token &token);

        bool readArray(Token &token);

        bool decodeNumber(Token &token);

        bool decodeString(Token &token);

        bool decodeString(Token &token, std::string &decoded);

        bool decodeDouble(Token &token);

        bool decodeUnicodeCodePoint(Token &token,
                                    Location &current,
                                    Location end,
                                    unsigned int &unicode);

        bool decodeUnicodeEscapeSequence(Token &token,
                                         Location &current,
                                         Location end,
                                         unsigned int &unicode);

        bool addError(const std::string &message,
                      Token &token,
                      Location extra);

        bool recoverFromError(TokenType skipUntilToken);

        bool addErrorAndRecover(const std::string &message,
                                Token &token,
                                TokenType skipUntilToken);

        void skipUntilSpace();

        Value &currentValue();

        Char getNextChar();

        void getLocationLineAndColumn(Location location,
                                      int &line,
                                      int &column) const;

        std::string getLocationLineAndColumn(Location location) const;

        void addComment(Location begin,
                        Location end,
                        CommentPlacement placement);

        void skipCommentTokens(Token &token);

        typedef std::stack<Value *> Nodes;
        Nodes nodes_;
        Errors errors_;
        std::string document_;
        Location begin_;
        Location end_;
        Location current_;
        Location lastValueEnd_;
        Value *lastValue_;
        std::string commentsBefore_;
        Features features_;
        bool collectComments_;
    };

    std::istream &operator>>(std::istream &, Value &);

} // namespace Json

#endif // CPPTL_JSON_READER_H_INCLUDED
