#include "MockContext.h"

#include <AideAttributes.h>
#include <CommonContext.h>
#include <StringTools.h>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace ComplianceEngine;
using ::testing::Return;

namespace
{
Result<std::string> ReadFile(const std::string& path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        return Error("Failed to read test file", errno);
    }
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::string QueryCommand(const AideAttributesParams& params)
{
    std::unique_ptr<char, decltype(&free)> canonical(realpath(params.filename.c_str(), nullptr), &free);
    if (!canonical)
    {
        return "";
    }
    return "aide --config \"" + EscapeForShell(params.configPath) + "\" -p \"f:" + EscapeForShell(canonical.get()) + "\"";
}
} // anonymous namespace

class AideAttributesTest : public ::testing::Test
{
protected:
    ::testing::StrictMock<MockContext> context;
    IndicatorsTree indicators;
    AideAttributesParams params;
    std::string command;

    void SetUp() override
    {
        indicators.Push("AideAttributes");
        params.configPath = "/etc/aide/aide.conf";
        params.filename = "/proc/self/exe";
        params.attributes = "p+i+n+u+g+s+b+acl+xattrs+sha512";
        std::unique_ptr<char, decltype(&free)> canonical(realpath(params.filename.c_str(), nullptr), &free);
        ASSERT_NE(canonical, nullptr);
        command = "aide --config \"/etc/aide/aide.conf\" -p \"f:" + EscapeForShell(canonical.get()) + "\"";
    }
};

TEST_F(AideAttributesTest, EffectiveAttributes)
{
    for (const auto& output : {"p+i+n+u+g+s+b+acl+xattrs+sha512\n", "p i n u g s b acl xattrs sha512 sha256\n"})
    {
        EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(output)));
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::Compliant);
    }
}

TEST_F(AideAttributesTest, MissingOrPartialAttributes)
{
    for (const auto& output : {"", "p+i+n+u+g+s+b+acl+xattrs\n", "p+i+n+u+g+s+b+acl+xattrs+sha512extra\n", "p+i+n+u+g+s+b+acl+xattrs-sha512\n",
             "p+i+n+u+g+s+b+acl+xattrs\nsha512\n"})
    {
        EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(output)));
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::NonCompliant);
    }
}

TEST_F(AideAttributesTest, QueryFailure)
{
    EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(Error("AIDE failed", 1))));
    auto result = AuditAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(AideAttributesTest, EveryAttributeIsRequired)
{
    std::istringstream attributes(params.attributes);
    std::string attribute;
    while (std::getline(attributes, attribute, '+'))
    {
        std::string output = params.attributes;
        output.replace(output.find(attribute), attribute.size(), "omitted");
        EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(output)));
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), Status::NonCompliant) << attribute;
        ASSERT_FALSE(indicators.Back().indicators.empty());
        EXPECT_EQ(indicators.Back().indicators.back().message,
            "Required AIDE attributes are missing for: " + params.filename + "; first missing attribute: " + attribute);
    }
}

TEST_F(AideAttributesTest, ExecutableFailureCannotBeHiddenByMatchingOutput)
{
    const std::string directory = context.GetTempdirPath() + "/aide \"$(printf dollar)`printf backtick`";
    ASSERT_EQ(0, mkdir(directory.c_str(), 0700));
    const std::string executable = directory + "/aide";
    const std::string selected = directory + "/tool \"$(id)`id`";
    const std::string link = directory + "/tool-link";
    std::ofstream(selected).close();
    ASSERT_EQ(symlink(selected.c_str(), link.c_str()), 0);
    params.filename = link;
    command = "aide --config \"/etc/aide/aide.conf\" -p \"f:" + EscapeForShell(selected) + "\"";
    CommonContext realContext(nullptr, directory);
    for (const int exitCode : {0, 1})
    {
        {
            std::ofstream script(executable);
            script << "#!/bin/sh\nprintf '%s\\n' 'p+i+n+u+g+s+b+acl+xattrs+sha512'\nexit " << exitCode << "\n";
        }
        ASSERT_EQ(chmod(executable.c_str(), 0700), 0);
        EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(::testing::Invoke([&](const std::string& query) {
            return realContext.ExecuteCommand("PATH=\"" + EscapeForShell(directory) + "\" " + query);
        }));
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), exitCode == 0 ? Status::Compliant : Status::NonCompliant);
    }
}

TEST_F(AideAttributesTest, MissingFile)
{
    params.filename = "/proc/self/nonexistent-aide-file";
    auto result = AuditAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);
}

TEST_F(AideAttributesTest, RejectInvalidArguments)
{
    for (const auto& attributes : {"sha512; echo injected", "", "+sha512", "sha512+", "p++sha512"})
    {
        params.attributes = attributes;
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_FALSE(result.HasValue());
        EXPECT_EQ(result.Error().code, EINVAL);
    }
    params.attributes = "sha512";
    params.configPath.clear();
    auto result = AuditAideAttributes(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);
}

TEST_F(AideAttributesTest, EscapeConfigPath)
{
    params.configPath = "/tmp/aide \"$(id)`id`\\.conf";
    command.replace(command.find("/etc/aide/aide.conf"), std::string("/etc/aide/aide.conf").size(), "/tmp/aide \\\"\\$(id)\\`id\\`\\\\.conf");
    EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>("p+i+n+u+g+s+b+acl+xattrs+sha512")));
    auto result = AuditAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);
}

TEST_F(AideAttributesTest, RemediateAddsValidatedExactFileRule)
{
    params.configPath = context.MakeTempfile("# existing configuration\n", ".conf");
    params.filename = context.MakeTempfile("protected", ".tool");
    command = QueryCommand(params);
    EXPECT_CALL(context, ExecuteCommand(command))
        .WillOnce(Return(Result<std::string>("p+i+n+u+g+s+b+acl+xattrs\n")))
        .WillOnce(Return(Result<std::string>(params.attributes + "\n")));
    EXPECT_CALL(context, GetFileContents(params.configPath)).WillOnce(::testing::Invoke([this](const std::string&) {
        return ReadFile(params.configPath);
    }));

    auto result = RemediateAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    auto config = ReadFile(params.configPath);
    ASSERT_TRUE(config.HasValue());
    EXPECT_EQ(config->find("# kompli:AideAttributes:"), 0);
    EXPECT_NE(config->find("%2Etool$ " + params.attributes + "\n# existing configuration\n"), std::string::npos);
}

TEST_F(AideAttributesTest, RemediateCompliantConfigurationIsNoOp)
{
    params.configPath = context.MakeTempfile("# existing configuration\n", ".conf");
    params.filename = context.MakeTempfile("protected", ".tool");
    command = QueryCommand(params);
    EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(params.attributes + "\n")));
    struct stat before;
    ASSERT_EQ(stat(params.configPath.c_str(), &before), 0);

    auto result = RemediateAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::Compliant);

    struct stat after;
    ASSERT_EQ(stat(params.configPath.c_str(), &after), 0);
    EXPECT_EQ(before.st_ino, after.st_ino);
}

TEST_F(AideAttributesTest, RemediateRollsBackFailedValidation)
{
    const std::string original = "# existing configuration\n";
    params.configPath = context.MakeTempfile(original, ".conf");
    params.filename = context.MakeTempfile("protected", ".tool");
    command = QueryCommand(params);
    EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>(""))).WillOnce(Return(Result<std::string>("p+i+n\n")));
    EXPECT_CALL(context, GetFileContents(params.configPath)).WillOnce(::testing::Invoke([this](const std::string&) {
        return ReadFile(params.configPath);
    }));

    auto result = RemediateAideAttributes(params, indicators, context);
    ASSERT_TRUE(result.HasValue());
    EXPECT_EQ(result.Value(), Status::NonCompliant);

    auto config = ReadFile(params.configPath);
    ASSERT_TRUE(config.HasValue());
    EXPECT_EQ(config.Value(), original);
}

TEST_F(AideAttributesTest, RemediateRejectsSymlinkConfiguration)
{
    const auto target = context.MakeTempfile("# existing configuration\n", ".conf");
    params.configPath = context.GetTempdirPath() + "/aide-link.conf";
    ASSERT_EQ(symlink(target.c_str(), params.configPath.c_str()), 0);
    params.filename = context.MakeTempfile("protected", ".tool");
    command = QueryCommand(params);
    EXPECT_CALL(context, ExecuteCommand(command)).WillOnce(Return(Result<std::string>("")));
    EXPECT_CALL(context, GetFileContents(params.configPath)).WillOnce(::testing::Invoke([target](const std::string&) { return ReadFile(target); }));

    auto result = RemediateAideAttributes(params, indicators, context);
    ASSERT_FALSE(result.HasValue());
    EXPECT_EQ(result.Error().code, EINVAL);

    auto config = ReadFile(target);
    ASSERT_TRUE(config.HasValue());
    EXPECT_EQ(config.Value(), "# existing configuration\n");
}
