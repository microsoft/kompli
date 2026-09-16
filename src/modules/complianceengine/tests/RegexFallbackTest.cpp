// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define USE_REGEX_FALLBACK 1
#include <RegexFallback.h>
#include <cstring>
#include <gtest/gtest.h>

class RegexFallbackTest : public ::testing::Test
{
};

TEST_F(RegexFallbackTest, NoMatch)
{
    std::string target = "This is a test string";
    std::string pattern = "notfound";

    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    EXPECT_FALSE(match.ready());

    bool result = regex_search(target, match, r);
    EXPECT_FALSE(result);
    ASSERT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
}

TEST_F(RegexFallbackTest, RangeSearchCapturesAndAnchors)
{
    const std::string contents = "ignored\nvalue=42\n";
    const regex pattern("^value=([0-9]+)");
    smatch match;
    EXPECT_FALSE(regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_continuous));
    ASSERT_TRUE(regex_search(contents.cbegin() + 8, contents.cend(), match, pattern, std::regex_constants::match_continuous));
    EXPECT_EQ(match.position(0), 0u);
    EXPECT_EQ(match.length(0), 8u);
    EXPECT_EQ(match[1].str(), "42");
    EXPECT_FALSE(regex_search(contents.cbegin() + 8, contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_TRUE(match.ready());
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexFallbackTest, RangeSearchPreservesPreviousCharacter)
{
    const std::string contents = "ab b";
    const regex pattern(R"(\b(b))");
    smatch match;
    ASSERT_TRUE(regex_search(contents.cbegin() + 1, contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_EQ(match.position(0), 2u);
    EXPECT_EQ(match.position(1), 2u);
    EXPECT_EQ(match[1].str(), "b");
    EXPECT_FALSE(regex_search(contents.cbegin() + 1, contents.cend(), match, pattern, std::regex_constants::match_prev_avail | std::regex_constants::match_continuous));
}

TEST_F(RegexFallbackTest, RangeSearchCanExcludeEmptyMatches)
{
    const std::string contents = "xb";
    const regex pattern("a*|b");
    smatch match;
    ASSERT_TRUE(regex_search(contents.cbegin(), contents.cend(), match, pattern));
    EXPECT_EQ(match.length(0), 0u);
    ASSERT_TRUE(regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_null));
    EXPECT_EQ(match.position(0), 1u);
    EXPECT_EQ(match[0].str(), "b");
    EXPECT_FALSE(regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_null | std::regex_constants::match_continuous));
    EXPECT_FALSE(regex_search(contents.cend(), contents.cend(), match, pattern, std::regex_constants::match_not_null));
    ASSERT_TRUE(regex_search(contents.cend(), contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_EQ(match.position(0), 0u);
    EXPECT_EQ(match.length(0), 0u);
}

TEST_F(RegexFallbackTest, RangeSearchHonorsBoundsAndEmbeddedNulls)
{
    std::string contents = "prefix";
    contents.push_back('\0');
    contents += "value=42";
    const regex pattern("value=([0-9]+)$");
    smatch match;
    ASSERT_TRUE(regex_search(contents.cbegin(), contents.cend(), match, pattern));
    EXPECT_EQ(match.position(0), 7u);
    EXPECT_EQ(match[1].str(), "42");
    EXPECT_FALSE(regex_search(contents.cbegin(), contents.cbegin() + 7, match, pattern));
    EXPECT_FALSE(regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_eol));
}

TEST_F(RegexFallbackTest, Match)
{
    std::string target = "This is a test string";
    std::string pattern = "test";

    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;

    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 1u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), 4u);
}

TEST_F(RegexFallbackTest, MatchWithSubMatches_1)
{
    std::string target = "This is a test string";
    std::string pattern = "(test)";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 2u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), std::strlen("test"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), std::strlen("test"));
}

TEST_F(RegexFallbackTest, MatchWithSubMatches_2)
{
    std::string target = "This is a test string";
    std::string pattern = "(test) (string)";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 3u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), std::strlen("test string"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), std::strlen("test"));
    EXPECT_EQ(match[2].matched, true);
    EXPECT_EQ(match[2].length(), std::strlen("string"));
}

TEST_F(RegexFallbackTest, MatchWithSubMatches_3)
{
    std::string target = "This is a test string";
    std::string pattern = "((test) (string))";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 4u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), std::strlen("test string"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), std::strlen("test string"));
    EXPECT_EQ(match[2].matched, true);
    EXPECT_EQ(match[2].length(), std::strlen("test"));
    EXPECT_EQ(match[3].matched, true);
    EXPECT_EQ(match[3].length(), std::strlen("string"));
    EXPECT_EQ(match[100].matched, false);
    EXPECT_EQ(match[100].length(), 0u);
}

TEST_F(RegexFallbackTest, RangeLoop)
{
    std::string target = "This is a test string";
    std::string pattern = "((test) (string))";
    std::string output;
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    for (const auto& m : match)
    {
        output += m.str();
    }
    EXPECT_EQ(output, "test stringtest stringteststring");
}

TEST_F(RegexFallbackTest, PrefixAndSuffix)
{
    std::string target = "This is a test string?";
    std::string pattern = "((test) (string))";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    EXPECT_EQ(match.prefix(), "This is a ");
    EXPECT_EQ(match.suffix(), "?");
}

TEST_F(RegexFallbackTest, RegexMatch_1)
{
    std::string target = "This is a test string?";
    std::string pattern = "((test) (string))";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_match(target, match, r);
    EXPECT_FALSE(result);
    EXPECT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexFallbackTest, RegexMatch_2)
{
    std::string target = "This is a test string?";
    std::string pattern = "This is a ((test) (string))";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_match(target, match, r);
    EXPECT_FALSE(result);
    EXPECT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexFallbackTest, RegexMatch_3)
{
    std::string target = "This is a test string?";
    std::string pattern = R"(This is a ((test) (string))\?)";
    auto r = regex(pattern, std::regex_constants::extended);
    smatch match;
    bool result = regex_match(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
}

TEST_F(RegexFallbackTest, RegexMatch_4)
{
    std::string target = "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so ";
    std::string pattern = R"(^[ \t]*account[ \t]+[^#\n\r]+[ \t]+pam_unix\.so\b)";
    auto r = regex(pattern);
    smatch match;
    bool result = regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
}
