// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "StringTools.h"

#include <gtest/gtest.h>

using ComplianceEngine::EscapeForShell;
using ComplianceEngine::TrimWhiteSpaces;

class StringToolsTest : public ::testing::Test
{
};

TEST_F(StringToolsTest, ToLowerPreservesNonLetters)
{
    EXPECT_EQ(ComplianceEngine::ToLower(""), "");
    EXPECT_EQ(ComplianceEngine::ToLower("MiXeD_123"), "mixed_123");
    EXPECT_EQ(ComplianceEngine::ToLower(std::string("A\0Z", 3)), std::string("a\0z", 3));
    EXPECT_EQ(ComplianceEngine::ToLower("A\x80\xff"), "a\x80\xff");
}

// Tests for EscapeForShell

TEST_F(StringToolsTest, EscapeForShell_EmptyString)
{
    EXPECT_EQ("", EscapeForShell(""));
}

TEST_F(StringToolsTest, EscapeForShell_NormalString)
{
    EXPECT_EQ("hello", EscapeForShell("hello"));
    EXPECT_EQ("hello world", EscapeForShell("hello world"));
    EXPECT_EQ("/path/to/file", EscapeForShell("/path/to/file"));
}

TEST_F(StringToolsTest, EscapeForShell_Backslashes)
{
    // Backslashes should be escaped
    EXPECT_EQ("\\\\", EscapeForShell("\\"));
    EXPECT_EQ("path\\\\to\\\\file", EscapeForShell("path\\to\\file"));
    EXPECT_EQ("\\\\n", EscapeForShell("\\n"));
    EXPECT_EQ("\\\\t", EscapeForShell("\\t"));
}

TEST_F(StringToolsTest, EscapeForShell_DoubleQuotes)
{
    // Double quotes should be escaped
    EXPECT_EQ("\\\"", EscapeForShell("\""));
    EXPECT_EQ("say \\\"hello\\\"", EscapeForShell("say \"hello\""));
    EXPECT_EQ("\\\"quoted\\\"", EscapeForShell("\"quoted\""));
}

TEST_F(StringToolsTest, EscapeForShell_Backticks)
{
    // Backticks should be escaped (command substitution)
    EXPECT_EQ("\\`", EscapeForShell("`"));
    EXPECT_EQ("\\`whoami\\`", EscapeForShell("`whoami`"));
    EXPECT_EQ("\\`id\\`", EscapeForShell("`id`"));
}

TEST_F(StringToolsTest, EscapeForShell_DollarSign)
{
    // Dollar signs should be escaped (variable expansion)
    EXPECT_EQ("\\$", EscapeForShell("$"));
    EXPECT_EQ("\\$HOME", EscapeForShell("$HOME"));
    EXPECT_EQ("\\$(whoami)", EscapeForShell("$(whoami)"));
    EXPECT_EQ("\\${USER}", EscapeForShell("${USER}"));
}

TEST_F(StringToolsTest, EscapeForShell_MultipleSpecialCharacters)
{
    // Multiple special characters should all be escaped
    EXPECT_EQ("\\\"\\$HOME\\\"", EscapeForShell("\"$HOME\""));
    EXPECT_EQ("\\`echo \\$USER\\`", EscapeForShell("`echo $USER`"));
    EXPECT_EQ("\\\\\\\"\\\\\\`\\$", EscapeForShell("\\\"\\`$"));
}

TEST_F(StringToolsTest, EscapeForShell_CommandInjectionPatterns)
{
    // Command injection patterns should be properly escaped
    EXPECT_EQ("; rm -rf /", EscapeForShell("; rm -rf /"));               // Semicolon not escaped
    EXPECT_EQ("&& malicious", EscapeForShell("&& malicious"));           // && not escaped
    EXPECT_EQ("| cat /etc/passwd", EscapeForShell("| cat /etc/passwd")); // Pipe not escaped

    // But these dangerous patterns with shell variables/commands should be escaped
    EXPECT_EQ("\\$(cat /etc/passwd)", EscapeForShell("$(cat /etc/passwd)"));
    EXPECT_EQ("\\`cat /etc/passwd\\`", EscapeForShell("`cat /etc/passwd`"));
}

TEST_F(StringToolsTest, EscapeForShell_MixedContent)
{
    // Real-world examples with mixed content
    EXPECT_EQ("hostname\\\"test\\\"", EscapeForShell("hostname\"test\""));
    EXPECT_EQ("user\\$name", EscapeForShell("user$name"));
    EXPECT_EQ("path\\\\with\\\\slashes", EscapeForShell("path\\with\\slashes"));
}

// Tests for TrimWhiteSpaces

TEST_F(StringToolsTest, TrimWhiteSpaces_EmptyString)
{
    EXPECT_EQ("", TrimWhiteSpaces(""));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_NoWhitespace)
{
    EXPECT_EQ("hello", TrimWhiteSpaces("hello"));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_LeadingWhitespace)
{
    EXPECT_EQ("hello", TrimWhiteSpaces("  hello"));
    EXPECT_EQ("hello", TrimWhiteSpaces("\thello"));
    EXPECT_EQ("hello", TrimWhiteSpaces("\nhello"));
    EXPECT_EQ("hello", TrimWhiteSpaces("  \t\nhello"));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_TrailingWhitespace)
{
    EXPECT_EQ("hello", TrimWhiteSpaces("hello  "));
    EXPECT_EQ("hello", TrimWhiteSpaces("hello\t"));
    EXPECT_EQ("hello", TrimWhiteSpaces("hello\n"));
    EXPECT_EQ("hello", TrimWhiteSpaces("hello  \t\n"));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_BothEnds)
{
    EXPECT_EQ("hello", TrimWhiteSpaces("  hello  "));
    EXPECT_EQ("hello world", TrimWhiteSpaces("  hello world  "));
    EXPECT_EQ("hello", TrimWhiteSpaces("\t\n hello \n\t"));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_OnlyWhitespace)
{
    EXPECT_EQ("", TrimWhiteSpaces("   "));
    EXPECT_EQ("", TrimWhiteSpaces("\t\n"));
    EXPECT_EQ("", TrimWhiteSpaces("  \t  \n  "));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_InternalWhitespace)
{
    // Internal whitespace should be preserved
    EXPECT_EQ("hello  world", TrimWhiteSpaces("  hello  world  "));
    EXPECT_EQ("hello\tworld", TrimWhiteSpaces("hello\tworld"));
}

TEST_F(StringToolsTest, TrimWhiteSpaces_PreservesHighBitBytes)
{
    EXPECT_EQ(std::string("\x80", 1), TrimWhiteSpaces(std::string(" \x80 ", 3)));
}

TEST_F(StringToolsTest, StripCommentLeavesWhitespaceForCaller)
{
    EXPECT_EQ("UID_MIN  1000 ", ComplianceEngine::StripComment("UID_MIN  1000 # users"));
    EXPECT_EQ("", ComplianceEngine::StripComment("# UID_MIN 0"));
    EXPECT_EQ("UID_MIN 1000", ComplianceEngine::StripComment("UID_MIN 1000"));
}

TEST_F(StringToolsTest, IntegerConversionRejectsUnconsumedSuffixes)
{
    for (const auto& value : {"5junk", "5 # comment", "5 ", "5\n", "5 6"})
    {
        const auto signedResult = ComplianceEngine::TryStringToInt(value);
        ASSERT_FALSE(signedResult.HasValue()) << value;
        EXPECT_EQ(signedResult.Error().code, EINVAL) << value;
        EXPECT_EQ(signedResult.Error().message, std::string("Invalid integer value: ") + value);

        const auto unsignedResult = ComplianceEngine::TryStringToUint(value);
        ASSERT_FALSE(unsignedResult.HasValue()) << value;
        EXPECT_EQ(unsignedResult.Error().code, EINVAL) << value;
    }
}

TEST_F(StringToolsTest, IntegerConversionKeepsLeadingWhitespaceSignsAndBases)
{
    auto signedResult = ComplianceEngine::TryStringToInt(" \t-12");
    ASSERT_TRUE(signedResult.HasValue());
    EXPECT_EQ(signedResult.Value(), -12);

    signedResult = ComplianceEngine::TryStringToInt("+12");
    ASSERT_TRUE(signedResult.HasValue());
    EXPECT_EQ(signedResult.Value(), 12);

    signedResult = ComplianceEngine::TryStringToInt("077", 8);
    ASSERT_TRUE(signedResult.HasValue());
    EXPECT_EQ(signedResult.Value(), 63);

    signedResult = ComplianceEngine::TryStringToInt("0x10", 0);
    ASSERT_TRUE(signedResult.HasValue());
    EXPECT_EQ(signedResult.Value(), 16);

    signedResult = ComplianceEngine::TryStringToInt("078", 8);
    ASSERT_FALSE(signedResult.HasValue());
    EXPECT_EQ(signedResult.Error().code, EINVAL);

    const auto unsignedResult = ComplianceEngine::TryStringToUint("-1");
    ASSERT_FALSE(unsignedResult.HasValue());
}

TEST_F(StringToolsTest, IntegerConversionRetainsOverflowAndInvalidErrors)
{
    const auto overflow = ComplianceEngine::TryStringToInt("2147483648");
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(overflow.Error().code, ERANGE);
    EXPECT_EQ(overflow.Error().message, "Integer value out of range: 2147483648");

    const auto invalid = ComplianceEngine::TryStringToInt("junk");
    ASSERT_FALSE(invalid.HasValue());
    EXPECT_EQ(invalid.Error().code, EINVAL);
}
