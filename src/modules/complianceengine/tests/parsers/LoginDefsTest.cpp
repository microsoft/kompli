// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <gtest/gtest.h>
#include <parsers/LoginDefs.h>
#include <string>
#include <utility>

namespace
{
namespace ld = ComplianceEngine::LoginDefs;

TEST(LoginDefsTest, EmptyAndCommentOnlyAreSuccessfulDocuments)
{
    const auto empty = ld::Parse("", "empty", nullptr);
    ASSERT_TRUE(empty.HasValue());
    EXPECT_EQ("empty", empty.Value().source);
    EXPECT_FALSE(empty.Value().uidMin.HasValue());

    const auto comments = ld::Parse(" \t# comment\n\n\t \n", "comments", nullptr);
    ASSERT_TRUE(comments.HasValue());
    EXPECT_FALSE(comments.Value().uidMin.HasValue());
}

TEST(LoginDefsTest, AcceptsMovedInputAndPreservesLvalueArguments)
{
    std::string bytes = "UID_MIN 1000\n";
    std::string source = "/etc/login.defs";
    const auto copied = ld::Parse(bytes, source, nullptr);
    ASSERT_TRUE(copied.HasValue());
    EXPECT_EQ("UID_MIN 1000\n", bytes);
    EXPECT_EQ("/etc/login.defs", source);
    ASSERT_TRUE(copied.Value().uidMin.HasValue());
    EXPECT_EQ(1000U, copied.Value().uidMin.Value());
    EXPECT_EQ(source, copied.Value().source);

    const auto moved = ld::Parse(std::move(bytes), std::move(source), nullptr);
    ASSERT_TRUE(moved.HasValue());
    ASSERT_TRUE(moved.Value().uidMin.HasValue());
    EXPECT_EQ("/etc/login.defs", moved.Value().source);
    EXPECT_EQ(1000U, moved.Value().uidMin.Value());
}

TEST(LoginDefsTest, AcceptsEquivalentKnownDuplicatesAndUnknownKeys)
{
    const auto parsed = ld::Parse(
        "# ignored\n  UID_MIN\t1000 \nUNRECOGNIZED yes\nUID_MIN 01000\n"
        "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD YESCRYPT\n"
        "UNRECOGNIZED no\nUID_MIN 1000\nPASS_MAX_DAYS 0365\nPASS_MIN_DAYS 1\n"
        "PASS_WARN_AGE 07\nENCRYPT_METHOD yescrypt\n",
        "logical", nullptr);
    ASSERT_TRUE(parsed.HasValue());
    const auto& doc = parsed.Value();
    EXPECT_EQ("logical", doc.source);
    ASSERT_TRUE(doc.uidMin.HasValue());
    EXPECT_EQ(1000U, doc.uidMin.Value());
    ASSERT_TRUE(doc.passMaxDays.HasValue());
    EXPECT_EQ(365, doc.passMaxDays.Value());
    ASSERT_TRUE(doc.passMinDays.HasValue());
    EXPECT_EQ(1, doc.passMinDays.Value());
    ASSERT_TRUE(doc.passWarnAge.HasValue());
    EXPECT_EQ(7, doc.passWarnAge.Value());
    ASSERT_TRUE(doc.encryptMethod.HasValue());
    EXPECT_EQ(ld::EncryptionMethod::YESCRYPT, doc.encryptMethod.Value());
}

TEST(LoginDefsTest, ConflictingKnownDuplicatesRejectWholeDocument)
{
    for (const std::string key : {"UID_MIN", "PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "ENCRYPT_METHOD"})
    {
        const std::string first = key == "ENCRYPT_METHOD" ? "SHA512" : "1";
        const std::string second = key == "ENCRYPT_METHOD" ? "YESCRYPT" : "2";
        const auto parsed = ld::Parse(key + " " + first + "\n" + key + " " + second + "\n", "source", nullptr);
        ASSERT_FALSE(parsed.HasValue()) << key;
        EXPECT_EQ(EBADMSG, parsed.Error().code) << key;
        EXPECT_EQ("source:2:" + std::to_string(key.size() + 2) + ": conflicting duplicate " + key + " value", parsed.Error().message);
    }
    EXPECT_TRUE(ld::Parse("UNKNOWN yes\nUNKNOWN no\n", "source", nullptr).HasValue());
}

TEST(LoginDefsTest, RejectsMalformedNumericValuesWithLocation)
{
    for (const std::string value : {"1000 # note", "1000#note", "\"1000#note\"", "1000 extra", "1000\\#note"})
    {
        const auto parsed = ld::Parse("UID_MIN " + value + "\n", "source", nullptr);
        ASSERT_FALSE(parsed.HasValue()) << value;
        EXPECT_EQ(EBADMSG, parsed.Error().code);
        EXPECT_NE(std::string::npos, parsed.Error().message.find("source:1:9: invalid UID_MIN value:")) << value;
    }
    const auto crlf = ld::Parse("UID_MIN 1000\r\n", "source", nullptr);
    ASSERT_TRUE(crlf.HasValue());
    EXPECT_EQ(1000U, crlf.Value().uidMin.Value());
}

TEST(LoginDefsTest, InvalidNumericValueInUnselectedKeyOrDuplicateRejectsDocument)
{
    const auto unrelated = ld::Parse("UID_MIN 1000\nPASS_MIN_DAYS 5junk\n", "source", nullptr);
    ASSERT_FALSE(unrelated.HasValue());
    EXPECT_EQ(EBADMSG, unrelated.Error().code);
    EXPECT_EQ("source:2:15: invalid PASS_MIN_DAYS value: Invalid integer value: 5junk", unrelated.Error().message);

    const auto duplicate = ld::Parse("UID_MIN 1000\nUID_MIN -1\n", "source", nullptr);
    ASSERT_FALSE(duplicate.HasValue());
    EXPECT_EQ("source:2:9: invalid UID_MIN value: Invalid integer value (should be positive): -1", duplicate.Error().message);

    const auto aboveSignedMax = ld::Parse("UID_MIN 2147483648\n", "source", nullptr);
    ASSERT_TRUE(aboveSignedMax.HasValue());
    ASSERT_TRUE(aboveSignedMax.Value().uidMin.HasValue());
    EXPECT_EQ(2147483648U, aboveSignedMax.Value().uidMin.Value());

    const auto maximum = ld::Parse("UID_MIN 4294967295\n", "source", nullptr);
    ASSERT_TRUE(maximum.HasValue());
    ASSERT_TRUE(maximum.Value().uidMin.HasValue());
    EXPECT_EQ(4294967295U, maximum.Value().uidMin.Value());

    const auto overflow = ld::Parse("UID_MIN 4294967296\n", "source", nullptr);
    ASSERT_FALSE(overflow.HasValue());
    EXPECT_EQ(EBADMSG, overflow.Error().code);
    EXPECT_EQ("source:1:9: invalid UID_MIN value: Integer value out of range: 4294967296", overflow.Error().message);
}

TEST(LoginDefsTest, AcceptsOnlyDocumentedEncryptionMethods)
{
    const struct
    {
        const char* value;
        ld::EncryptionMethod method;
    } cases[] = {
        {"DES", ld::EncryptionMethod::DES},
        {"MD5", ld::EncryptionMethod::MD5},
        {"SHA256", ld::EncryptionMethod::SHA256},
        {"SHA512", ld::EncryptionMethod::SHA512},
        {"YESCRYPT", ld::EncryptionMethod::YESCRYPT},
        {"BCRYPT", ld::EncryptionMethod::BCRYPT},
    };
    for (const auto& item : cases)
    {
        const auto parsed = ld::Parse(std::string("ENCRYPT_METHOD ") + item.value + "\n", "source", nullptr);
        ASSERT_TRUE(parsed.HasValue()) << item.value;
        ASSERT_TRUE(parsed.Value().encryptMethod.HasValue());
        EXPECT_EQ(item.method, parsed.Value().encryptMethod.Value());
        EXPECT_EQ(item.value, std::string(ld::EncryptionMethodName(item.method)));
    }
    const auto parsed = ld::Parse("ENCRYPT_METHOD yescrypt \r\nOTHER 5junk\n", "source", nullptr);
    ASSERT_TRUE(parsed.HasValue());
    ASSERT_TRUE(parsed.Value().encryptMethod.HasValue());
    EXPECT_EQ(ld::EncryptionMethod::YESCRYPT, parsed.Value().encryptMethod.Value());
}

TEST(LoginDefsTest, RejectsUndocumentedEncryptionMethodsEvenOnLaterOccurrence)
{
    for (const std::string value : {"SHA-512", "Blowfish", "None", "yescrypt\x80", "\"YESCRYPT\"", "YESCRYPT extra", "\"\""})
    {
        const auto parsed = ld::Parse("ENCRYPT_METHOD " + value + "\n", "source", nullptr);
        ASSERT_FALSE(parsed.HasValue()) << value;
        EXPECT_EQ(EBADMSG, parsed.Error().code);
        EXPECT_EQ("source:1:16: invalid ENCRYPT_METHOD value: Unsupported encryption method: " + value, parsed.Error().message);
    }
    const auto duplicate = ld::Parse("ENCRYPT_METHOD SHA512\nENCRYPT_METHOD unsupported\n", "source", nullptr);
    ASSERT_FALSE(duplicate.HasValue());
    EXPECT_EQ(EBADMSG, duplicate.Error().code);
    EXPECT_TRUE(ld::Parse("OTHER 5junk\n", "source", nullptr).HasValue());
}

TEST(LoginDefsTest, MissingValueRejectsWholeDocumentWithLocation)
{
    const auto parsed = ld::Parse("UID_MIN 1000\nUNKNOWN\nUID_MIN 2000\n", "source", nullptr);
    ASSERT_FALSE(parsed.HasValue());
    EXPECT_EQ(EBADMSG, parsed.Error().code);
    EXPECT_EQ("source:2:8: login.defs missing value", parsed.Error().message);
    const auto whitespace = ld::Parse("UID_MIN \t\n", "source", nullptr);
    ASSERT_FALSE(whitespace.HasValue());
    EXPECT_EQ("source:1:10: login.defs missing value", whitespace.Error().message);
    EXPECT_TRUE(ld::Parse("OTHER \"\"\n", "source", nullptr).HasValue());
}

TEST(LoginDefsTest, EmbeddedNulRejectsWholeDocumentWithByteLocation)
{
    const std::string input = std::string("UID_MIN 1000\0junk\nUID_MIN 2000\n", 31);
    const auto parsed = ld::Parse(input, "source", nullptr);
    ASSERT_FALSE(parsed.HasValue());
    EXPECT_EQ(EBADMSG, parsed.Error().code);
    EXPECT_EQ("source:1:13: login.defs embedded NUL", parsed.Error().message);

    const auto later = ld::Parse(std::string("UID_MIN 1000\n#\0ignored\n", 23), "source", nullptr);
    ASSERT_FALSE(later.HasValue());
    EXPECT_EQ("source:2:2: login.defs embedded NUL", later.Error().message);
}

TEST(LoginDefsTest, RejectsFirstEmbeddedNulOnTheSameLine)
{
    const std::string input("UID_MIN 1\0a\0b\n", 14);
    const auto parsed = ld::Parse(input, "source", nullptr);
    ASSERT_FALSE(parsed.HasValue());
    EXPECT_EQ(EBADMSG, parsed.Error().code);
    EXPECT_EQ("source:1:10: login.defs embedded NUL", parsed.Error().message);
}

TEST(LoginDefsTest, ByteBudgetRejectsOversizeInsteadOfReturningPartialDocument)
{
    std::string input;
    input.reserve(ld::MaxBytes + 1);
    for (std::size_t i = 0; i < ld::MaxBytes / 2; ++i)
    {
        input += "#\n";
    }
    EXPECT_TRUE(ld::Parse(input.substr(0, ld::MaxBytes - 1), "source", nullptr).HasValue());
    EXPECT_TRUE(ld::Parse(input.substr(0, ld::MaxBytes), "source", nullptr).HasValue());
    const auto excess = ld::Parse(input + "x", "source", nullptr);
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

TEST(LoginDefsTest, LineBudgetChecksBothSidesOfBoundary)
{
    const std::string line(ld::MaxLineBytes, '#');
    EXPECT_TRUE(ld::Parse(line.substr(0, ld::MaxLineBytes - 1), "source", nullptr).HasValue());
    EXPECT_TRUE(ld::Parse(line, "source", nullptr).HasValue());
    const auto excess = ld::Parse(line + "#", "source", nullptr);
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

TEST(LoginDefsTest, RecordBudgetChecksBothSidesOfBoundary)
{
    std::string records;
    for (std::size_t i = 0; i <= ld::MaxRecords; ++i)
    {
        records += "K 1\n";
    }
    EXPECT_TRUE(ld::Parse(records.substr(0, 4 * (ld::MaxRecords - 1)), "source", nullptr).HasValue());
    EXPECT_TRUE(ld::Parse(records.substr(0, 4 * ld::MaxRecords), "source", nullptr).HasValue());
    const auto excess = ld::Parse(records, "source", nullptr);
    ASSERT_FALSE(excess.HasValue());
    EXPECT_EQ(E2BIG, excess.Error().code);
}

} // anonymous namespace
