// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstring>
#include <gtest/gtest.h>
#include <regex>

class RegexTest : public ::testing::Test
{
};

TEST_F(RegexTest, NoMatch)
{
    std::string input = "This is a test string";
    std::string pattern = "notfound";

    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    EXPECT_FALSE(match.ready());

    bool result = std::regex_search(input, match, r);
    EXPECT_FALSE(result);
    ASSERT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
}

TEST_F(RegexTest, Match)
{
    std::string input = "This is a test string";
    std::string pattern = "test";

    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;

    bool result = std::regex_search(input, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 1u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), 4u);
}

TEST_F(RegexTest, DefaultSyntaxIsECMAScript)
{
    const std::string input = "value=42";
    const std::regex pattern(R"(\d+(?=$))");
    std::smatch match;

    ASSERT_TRUE(std::regex_search(input, match, pattern));
    EXPECT_EQ(match[0].str(), "42");
}

TEST_F(RegexTest, RangeSearchCapturesAndAnchors)
{
    const std::string contents = "ignored\nvalue=42\n";
    const std::regex pattern("^value=([0-9]+)");
    std::smatch match;
    EXPECT_FALSE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_continuous));
    ASSERT_TRUE(std::regex_search(contents.cbegin() + 8, contents.cend(), match, pattern, std::regex_constants::match_continuous));
    EXPECT_EQ(match.position(0), 0);
    EXPECT_EQ(match.length(0), 8);
    EXPECT_EQ(match[1].str(), "42");
    EXPECT_FALSE(std::regex_search(contents.cbegin() + 8, contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_TRUE(match.ready());
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexTest, RangeSearchPreservesPreviousCharacter)
{
    const std::string contents = "ab b";
    const std::regex pattern(R"(\b(b))");
    std::smatch match;
    ASSERT_TRUE(std::regex_search(contents.cbegin() + 1, contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_EQ(match.position(0), 2);
    EXPECT_EQ(match.position(1), 2);
    EXPECT_EQ(match[1].str(), "b");
    EXPECT_FALSE(std::regex_search(contents.cbegin() + 1, contents.cend(), match, pattern,
        std::regex_constants::match_prev_avail | std::regex_constants::match_continuous));
}

TEST_F(RegexTest, RangeSearchCanExcludeEmptyMatches)
{
    const std::string contents = "xb";
    const std::regex pattern("a*|b");
    std::smatch match;
    ASSERT_TRUE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern));
    EXPECT_EQ(match.length(0), 0);
    ASSERT_TRUE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_null));
    EXPECT_EQ(match.position(0), 1);
    EXPECT_EQ(match[0].str(), "b");
    EXPECT_FALSE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_null | std::regex_constants::match_continuous));
    EXPECT_FALSE(std::regex_search(contents.cend(), contents.cend(), match, pattern, std::regex_constants::match_not_null));
    ASSERT_TRUE(std::regex_search(contents.cend(), contents.cend(), match, pattern, std::regex_constants::match_prev_avail));
    EXPECT_EQ(match.position(0), 0);
    EXPECT_EQ(match.length(0), 0);
}

TEST_F(RegexTest, RangeSearchHonorsBoundsAndEmbeddedNulls)
{
    std::string contents = "prefix";
    contents.push_back('\0');
    contents += "value=42";
    const std::regex pattern("value=([0-9]+)$");
    std::smatch match;
    ASSERT_TRUE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern));
    EXPECT_EQ(match.position(0), 7);
    EXPECT_EQ(match[1].str(), "42");
    EXPECT_FALSE(std::regex_search(contents.cbegin(), contents.cbegin() + 7, match, pattern));
    EXPECT_FALSE(std::regex_search(contents.cbegin(), contents.cend(), match, pattern, std::regex_constants::match_not_eol));
}

TEST_F(RegexTest, MatchWithSubMatches_1)
{
    std::string input = "This is a test string";
    std::string pattern = "(test)";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_search(input, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 2u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), (ssize_t)std::strlen("test"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), (ssize_t)std::strlen("test"));
}

TEST_F(RegexTest, MatchWithSubMatches_2)
{
    std::string input = "This is a test string";
    std::string pattern = "(test) (string)";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_search(input, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 3u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), (ssize_t)std::strlen("test string"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), (ssize_t)std::strlen("test"));
    EXPECT_EQ(match[2].matched, true);
    EXPECT_EQ(match[2].length(), (ssize_t)std::strlen("string"));
}

TEST_F(RegexTest, MatchWithSubMatches_3)
{
    std::string input = "This is a test string";
    std::string pattern = "((test) (string))";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_search(input, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    ASSERT_EQ(match.size(), 4u);
    EXPECT_EQ(match[0].matched, true);
    EXPECT_EQ(match[0].length(), (ssize_t)std::strlen("test string"));
    EXPECT_EQ(match[1].matched, true);
    EXPECT_EQ(match[1].length(), (ssize_t)std::strlen("test string"));
    EXPECT_EQ(match[2].matched, true);
    EXPECT_EQ(match[2].length(), (ssize_t)std::strlen("test"));
    EXPECT_EQ(match[3].matched, true);
    EXPECT_EQ(match[3].length(), (ssize_t)std::strlen("string"));
    EXPECT_EQ(match[100].matched, false);
    EXPECT_EQ(match[100].length(), 0);
}

TEST_F(RegexTest, RangeLoop)
{
    std::string input = "This is a test string";
    std::string pattern = "((test) (string))";
    std::string output;
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_search(input, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    for (const auto& m : match)
    {
        output += m.str();
    }
    EXPECT_EQ(output, "test stringtest stringteststring");
}

TEST_F(RegexTest, PrefixAndSuffix)
{
    std::string target = "This is a test string?";
    std::string pattern = "((test) (string))";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_search(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
    EXPECT_EQ(match.prefix(), "This is a ");
    EXPECT_EQ(match.suffix(), "?");
}

TEST_F(RegexTest, RegexMatch_1)
{
    std::string target = "This is a test string?";
    std::string pattern = "((test) (string))";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_match(target, match, r);
    EXPECT_FALSE(result);
    EXPECT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexTest, RegexMatch_2)
{
    std::string target = "This is a test string?";
    std::string pattern = "This is a ((test) (string))";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_match(target, match, r);
    EXPECT_FALSE(result);
    EXPECT_TRUE(match.ready());
    EXPECT_EQ(match.size(), 0u);
    EXPECT_TRUE(match.empty());
}

TEST_F(RegexTest, RegexMatch_3)
{
    std::string target = "This is a test string?";
    std::string pattern = R"(This is a ((test) (string))\?)";
    auto r = std::regex(pattern, std::regex_constants::extended);
    std::smatch match;
    bool result = std::regex_match(target, match, r);
    EXPECT_TRUE(result);
    ASSERT_TRUE(match.ready());
}
