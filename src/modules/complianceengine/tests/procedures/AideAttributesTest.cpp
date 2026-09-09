#include "MockContext.h"

#include <AideAttributes.h>
#include <CommonContext.h>
#include <StringTools.h>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace ComplianceEngine;
using ::testing::Return;

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
    }
}

TEST_F(AideAttributesTest, ExecutableFailureCannotBeHiddenByMatchingOutput)
{
    char directoryTemplate[] = "/tmp/aide-attributes-XXXXXX";
    char* directory = mkdtemp(directoryTemplate);
    ASSERT_NE(directory, nullptr);
    const std::string executable = std::string(directory) + "/aide";
    const std::string selected = std::string(directory) + "/tool \"$(id)`id`";
    const std::string link = std::string(directory) + "/tool-link";
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
            return realContext.ExecuteCommand("PATH=\"" + std::string(directory) + "\" " + query);
        }));
        auto result = AuditAideAttributes(params, indicators, context);
        ASSERT_TRUE(result.HasValue());
        EXPECT_EQ(result.Value(), exitCode == 0 ? Status::Compliant : Status::NonCompliant);
    }
    EXPECT_EQ(unlink(link.c_str()), 0);
    EXPECT_EQ(unlink(selected.c_str()), 0);
    EXPECT_EQ(unlink(executable.c_str()), 0);
    EXPECT_EQ(rmdir(directory), 0);
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
        EXPECT_FALSE(AuditAideAttributes(params, indicators, context).HasValue());
    }
    params.attributes = "sha512";
    params.configPath.clear();
    EXPECT_FALSE(AuditAideAttributes(params, indicators, context).HasValue());
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
